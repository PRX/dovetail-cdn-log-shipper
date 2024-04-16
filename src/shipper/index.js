const AWS = require("aws-sdk");
const s3 = new AWS.S3();
const zlib = require("zlib");
const util = require("util");
const gunzip = util.promisify(zlib.gunzip);
const gzip = util.promisify(zlib.gzip);
const crypto = require("crypto");

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

const hashValue = (val) => {
  const hmac = crypto.createHmac("sha256", process.env.SECRET_KEY || "");
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

const PODCAST_IDS = process.env.PODCAST_IDS.split(",")
  .map((s) => s.trim())
  .filter((s) => s);

const IGNORE_PATHS = ["/", "/favicon.ico", "/robots.txt"];

exports.handler = async (event) => {
  for (const rec of event.Records) {
    const Bucket = rec.s3.bucket.name;
    const Key = rec.s3.object.key;
    const result = await s3.getObject({ Bucket, Key }).promise();
    const log = await gunzip(result.Body);
    const rows = log
      .toString("utf-8")
      .split("\n")
      .filter((r) => r)
      .map((r) => r.split("\t"));

    // ensure we know what this is
    const version = rows.shift()[0];
    if (version !== "#Version: 1.0") {
      throw new Error(`Unsupported CloudFront Log Version: ${version}`);
    }

    // get fieldnames from comment
    const fields = rows
      .shift()[0]
      .replace(/^#Fields: /, "")
      .split(" ");
    const mappedRows = rows.map((row) => {
      return row.reduce(
        (acc, val, idx) => ({ ...acc, [fields[idx]]: val }),
        {},
      );
    });

    // podcast id and episode guid (only works for dovetail3-cdn requests)
    const datas = mappedRows.filter((data) => {
      const parts = data["cs-uri-stem"].split("/").filter((s) => s);

      // if the path starts with a region like usw2, shift that off
      if (parts[0] && parts[0].match(/^[a-z][a-z0-9\-]+$/)) {
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
      return PODCAST_IDS.includes(data["prx-podcast-id"]);
    });
    fields.push("prx-podcast-id");
    fields.push("prx-episode-guid");

    // calculate listener_ids
    datas.forEach((data) => {
      // use leftmost XFF or IP
      const leftMostIp = findIp(data["x-forwarded-for"], data["c-ip"]);

      // truncate ipv6 but not ipv4
      const truncatedIp = leftMostIp.includes(":")
        ? maskIp(leftMostIp, "listener-id")
        : leftMostIp;

      // combine with UA string
      const userAgent = data["cs(User-Agent)"] || "";
      data["prx-listener-id"] = hashValue(truncatedIp + userAgent);

      // also provide just the hashed IP, use truncated ipv6
      data["prx-hashed-ip"] = hashValue(truncatedIp);
    });
    fields.push("prx-listener-id");
    fields.push("prx-hashed-ip");

    // mask IP addresses
    datas.forEach((data) => {
      data["c-ip"] = maskIp(data["c-ip"], "c-ip");
      const xffParts = (data["x-forwarded-for"] || "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s);
      data["x-forwarded-for"] = xffParts
        .map((ip) => maskIp(ip, "x-forwarded-for"))
        .join(", ");
    });

    // write to tsv and gzip
    const tsv =
      fields.join("\t") +
      "\n" +
      datas
        .map((data) => {
          return fields.map((f) => data[f] || "").join("\t");
        })
        .join("\n");
    const buffer = await gzip(tsv);

    // send to s3 destinations
    const bucket_names = process.env.DESTINATION_BUCKET.split(",");
    for (const bucket_name of bucket_names) {
      const params = {
        Bucket: bucket_name,
        Key: `${process.env.DESTINATION_PREFIX}/${Key.split("/").pop()}`,
        ACL: "bucket-owner-full-control",
        Body: buffer,
      };
      if (datas.length > 0) {
        await s3.putObject(params).promise();
      }

      console.info(
        `Shipped ${datas.length} of ${rows.length} to s3://${params.Bucket}/${params.Key}`,
      );
    }
  }
};
