import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

const s3Client = new S3Client({});

import crypto from "crypto";
import util from "util";
import zlib from "zlib";

const gunzip = util.promisify(zlib.gunzip);
const gzip = util.promisify(zlib.gzip);

let cachedConfigs;

export const s3 = s3Client;

export const resetCachedConfigs = () => {
  cachedConfigs = undefined;
};

export const loadConfigs = async () => {
  if (cachedConfigs) {
    return cachedConfigs;
  }

  const configBucket = process.env.CONFIG_BUCKET;
  const configKey = process.env.CONFIG_KEY;

  if (!configBucket || !configKey) {
    throw new Error(
      "CONFIG_BUCKET and CONFIG_KEY environment variables must be set.",
    );
  }

  try {
    console.log(
      `Loading configurations from s3://${configBucket}/${configKey}`,
    );
    const { Body } = await s3Client.send(
      new GetObjectCommand({ Bucket: configBucket, Key: configKey }),
    );
    const configBody = await Body.transformToString();
    cachedConfigs = JSON.parse(configBody);
    console.log("Configurations loaded successfully.");
    return cachedConfigs;
  } catch (error) {
    console.error(`Error loading configurations from S3: ${error.message}`);
    throw error;
  }
};

const IPV4_MASK = /\.[0-9]{1,3}$/;

const maskIp = (ip, field) => {
  if (ip.match(IPV4_MASK)) {
    return ip.replace(IPV4_MASK, ".0");
  } else if (ip.includes(":")) {
    // take up to 4 chunks - drop the rest
    const chunks = ip.split(":").slice(0, 4);

    // remove all trailing ':', then add '::' (zeroes)
    return chunks.join(":").replace(/:+$/, "") + "::";
  } else if (ip === "-") {
    // that's ok
  } else {
    console.warn(`Unrecognized ${field}: ${ip}`);
    return ip;
  }
};

const hashValue = (val, secretKey) => {
  const hmac = crypto.createHmac("sha256", secretKey);
  hmac.update(val);
  return hmac.digest("base64").replace(/\+|\/|=/g, (m) => {
    if (m === "+") {
      return "-";
    }
    if (m === "/") {
      return "_";
    }
    return "";
  });
};

const findIp = (xff, ip) => {
  if (xff === "-") {
    return ip;
  } else if (xff) {
    return xff
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s)[0];
  } else {
    return ip;
  }
};

export const handler = async (event) => {
  const configs = await loadConfigs();

  for (const rec of event.Records) {
    const Bucket = rec.s3.bucket.name;
    const Key = rec.s3.object.key;
    const result = await s3Client.send(new GetObjectCommand({ Bucket, Key }));
    const bodyBuffer = await result.Body.transformToByteArray();
    const log = await gunzip(bodyBuffer);
    const rows = log
      .toString("utf-8")
      .split("\n")
      .filter((r) => r)
      .map((r) => r.split("\t"));

    // The initial rows contain metadata and fieldnames, we need to process those first
    const initialRows = rows.slice(0, 2);

    // ensure we know what this is
    const version = initialRows[0][0];
    if (version !== "#Version: 1.0") {
      throw new Error(`Unsupported CloudFront Log Version: ${version}`);
    }

    // get fieldnames from comment
    const fieldsLine = initialRows[1][0];
    const originalFields = fieldsLine.replace(/^#Fields: /, "").split(" ");

    // skip the initial rows, map the rest to objects with fieldnames as keys
    const mappedRows = rows.slice(2).map((row) => {
      return originalFields.reduce(
        (acc, val, idx) => ({ ...acc, [originalFields[idx]]: row[idx] }),
        {},
      );
    });

    mappedRows.forEach((data) => {
      // save the original IP and XFF for later use, since sometimes we anonymize them
      data["prx-original-ip"] = data["c-ip"];
      data["prx-original-xff"] = data["x-forwarded-for"];
    });

    // Process for each configuration
    for (const currentConfig of configs) {
      const PODCAST_IDS = currentConfig.PODCAST_IDS;
      const IGNORE_PATHS = currentConfig.IGNORE_PATHS || [
        "/",
        "/favicon.ico",
        "/robots.txt",
      ];
      const SECRET_KEY = currentConfig.SECRET_KEY;
      const DESTINATION_BUCKET = currentConfig.DESTINATION_BUCKET;
      const DESTINATION_PREFIX = currentConfig.DESTINATION_PREFIX;

      // podcast id and episode guid (only works for dovetail3-cdn requests)
      const datas = mappedRows.filter((data) => {
        const parts = data["cs-uri-stem"].split("/").filter((s) => s);

        // if the path starts with a region like usw2, shift that off
        if (parts[0] && parts[0].match(/^[a-z][a-z0-9-]+$/)) {
          parts.shift();
        }

        if (parts.length === 4) {
          data["prx-podcast-id"] = parts[0];
          data["prx-episode-guid"] = parts[1];
        } else if (parts.length === 5) {
          data["prx-podcast-id"] = parts[0];
          data["prx-episode-guid"] = parts[2];
        } else if (!IGNORE_PATHS.includes(data["cs-uri-stem"])) {
          console.warn(`Non-dovetail3 uri: ${data["cs-uri-stem"]}`);
        }

        // Ensure PODCAST_IDS are numbers for comparison if data["prx-podcast-id"] is a string
        return PODCAST_IDS.includes(parseInt(data["prx-podcast-id"]));
      });

      const currentFields = [...originalFields];
      currentFields.push("prx-podcast-id");
      currentFields.push("prx-episode-guid");

      // calculate listener_ids
      datas.forEach((data) => {
        // use leftmost XFF or IP, from the original values
        const leftMostIp = findIp(
          data["prx-original-xff"],
          data["prx-original-ip"],
        );

        // truncate ipv6 but not ipv4
        const truncatedIp = leftMostIp.includes(":")
          ? maskIp(leftMostIp, "listener-id")
          : leftMostIp;

        // combine with UA string
        const userAgent = data["cs(User-Agent)"] || "";
        data["prx-listener-id"] = hashValue(
          truncatedIp + userAgent,
          SECRET_KEY,
        );

        // also provide just the hashed IP, use truncated ipv6
        data["prx-hashed-ip"] = hashValue(truncatedIp, SECRET_KEY);
      });
      currentFields.push("prx-listener-id");
      currentFields.push("prx-hashed-ip");

      // mask IP addresses if not FULL_IPS
      datas.forEach((data) => {
        if (currentConfig.FULL_IPS) {
          // restore the c-ip and x-forwarded-for from the original values
          data["c-ip"] = data["prx-original-ip"];
          data["x-forwarded-for"] = data["prx-original-xff"];
        } else {
          // mask c-ip and x-forwarded-for (using the original values, not the possibly masked ones)
          data["c-ip"] = maskIp(data["prx-original-ip"], "c-ip");
          const xffParts = (data["prx-original-xff"] || "")
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s);
          data["x-forwarded-for"] = xffParts
            .map((ip) => maskIp(ip, "x-forwarded-for"))
            .join(", ");
        }
      });

      // write to tsv and gzip
      const tsv =
        currentFields.join("\t") +
        "\n" +
        datas
          .map((data) => {
            return currentFields.map((f) => data[f] || "").join("\t");
          })
          .join("\n");
      const buffer = await gzip(tsv);

      // send to s3 destinations
      const bucket_names = DESTINATION_BUCKET;
      for (const bucket_name of bucket_names) {
        if (datas.length > 0) {
          await s3Client.send(
            new PutObjectCommand({
              Bucket: bucket_name,
              Key: `${DESTINATION_PREFIX}/${Key.split("/").pop()}`,
              Body: buffer,
              ACL: "bucket-owner-full-control",
            }),
          );
        }

        console.info(
          `Shipped ${datas.length} of ${rows.length} to s3://${bucket_name}/${DESTINATION_PREFIX}/${Key.split("/").pop()}`,
        );
      }
    }
  }
};
