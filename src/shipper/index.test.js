import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import { sdkStreamMixin } from "@aws-sdk/util-stream-node";
import { Readable } from "stream";
import zlib from "zlib";
import util from "util";
import crypto from "crypto";

const gunzip = util.promisify(zlib.gunzip);
const gzip = util.promisify(zlib.gzip);

// Mock environment variables
const ORIGINAL_CONFIG_BUCKET = process.env.CONFIG_BUCKET;
const ORIGINAL_CONFIG_KEY = process.env.CONFIG_KEY;

let s3Mock;
let s3;
let loadConfigs;
let handler;
let resetCachedConfigs;

// Dynamically import the module after setting up mocks
beforeAll(async () => {
  const module = await import("./index.js");
  s3 = module.s3;
  loadConfigs = module.loadConfigs;
  handler = module.handler;
  resetCachedConfigs = module.resetCachedConfigs;
});

beforeEach(() => {
  s3Mock = mockClient(S3Client);
  s3Mock.reset();
  resetCachedConfigs();
  process.env.CONFIG_BUCKET = "test-config-bucket";
  process.env.CONFIG_KEY = "test-config.json";
});

afterAll(() => {
  process.env.CONFIG_BUCKET = ORIGINAL_CONFIG_BUCKET;
  process.env.CONFIG_KEY = ORIGINAL_CONFIG_KEY;
});

describe("Utility functions", () => {
  // These functions are not exported, so we will test their behavior through the `handler`'s output.
  // The logic for these functions is covered in the handler tests.
});

describe("loadConfigs", () => {
  test("should load configurations successfully from S3", async () => {
    const mockConfig = [
      {
        PODCAST_IDS: [1, 2, 3],
        IGNORE_PATHS: ["/ignore"],
        SECRET_KEY: "secret",
        DESTINATION_BUCKET: ["destination-bucket"],
        DESTINATION_PREFIX: "prefix",
      },
    ];
    const configBuffer = Buffer.from(JSON.stringify(mockConfig), "utf-8");

    s3Mock.on(GetObjectCommand).resolves({
      Body: sdkStreamMixin(Readable.from([configBuffer])),
    });

    const configs = await loadConfigs();
    expect(configs).toEqual(mockConfig);
    expect(s3Mock.calls().length).toBe(1);
    expect(s3Mock.call(0).args[0].input).toEqual({
      Bucket: "test-config-bucket",
      Key: "test-config.json",
    });
  });

  test("should throw error if CONFIG_BUCKET or CONFIG_KEY are not set", async () => {
    delete process.env.CONFIG_BUCKET;
    delete process.env.CONFIG_KEY;
    await expect(loadConfigs()).rejects.toThrow(
      "CONFIG_BUCKET and CONFIG_KEY environment variables must be set.",
    );
  });

  test("should throw error if S3 GetObjectCommand fails", async () => {
    s3Mock.on(GetObjectCommand).rejects(new Error("S3 error"));
    await expect(loadConfigs()).rejects.toThrow("S3 error");
  });
});

describe("handler", () => {
  beforeEach(() => {
    s3Mock.reset();
    resetCachedConfigs();
    process.env.CONFIG_BUCKET = "test-config-bucket";
    process.env.CONFIG_KEY = "test-config.json";
  });

  test("should process S3 event and put processed logs to destination S3", async () => {
    const mockConfig = [
      {
        PODCAST_IDS: [1],
        IGNORE_PATHS: [],
        SECRET_KEY: "test-secret",
        DESTINATION_BUCKET: ["destination-bucket-1"],
        DESTINATION_PREFIX: "processed-logs",
      },
    ];
    const configBuffer = Buffer.from(JSON.stringify(mockConfig), "utf-8");

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "test-config-bucket",
        Key: "test-config.json",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([configBuffer])),
      });

    const mockLogContent = `
#Version: 1.0
#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem cs-uri-query sc-status cs(Referer) cs(User-Agent) cs-uri-stem(truncated) cs-uri-query(truncated) x-forwarded-for
2023-01-01\t00:00:00\tLHR50\t100\t192.168.1.1\tGET\texample.com\t/1/episode-a-guid/arr1/file.mp3\t-\t200\t-\tMozilla/5.0\t/1/episode-a-guid/arr1/file.mp3\t-\t-
2023-01-01\t00:00:00\tLHR50\t100\t192.168.1.2\tGET\texample.com\t/2/episode-b-guid/arr2/file.mp3\t-\t200\t-\tMozilla/5.0\t/2/episode-b-guid/arr2/file.mp3\t-\t-
2023-01-01\t00:00:00\tLHR50\t100\t192.168.1.3\tGET\texample.com\t/3/episode-c-guid/arr3/file.mp3\t-\t200\t-\tMozilla/5.0\t/3/episode-c-guid/arr3/file.mp3\t-\t-`;

    const gzippedLogBuffer = await gzip(
      new Uint8Array(Buffer.from(mockLogContent, "utf-8")),
    );

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "source-bucket",
        Key: "logs/test-log.gz",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([gzippedLogBuffer])),
      });

    const s3Event = {
      Records: [
        {
          s3: {
            bucket: { name: "source-bucket" },
            object: { key: "logs/test-log.gz" },
          },
        },
      ],
    };

    await handler(s3Event);

    // Expect PutObjectCommand to be called
    expect(s3Mock.call(2).args[0].input.Bucket).toBe("destination-bucket-1");
    expect(s3Mock.call(2).args[0].input.Key).toBe("processed-logs/test-log.gz");

    const processedBuffer = s3Mock.call(2).args[0].input.Body;
    const gunzippedProcessed = await gunzip(processedBuffer);
    const processedContent = gunzippedProcessed.toString("utf-8");

    const expectedHeader =
      "date\ttime\tx-edge-location\tsc-bytes\tc-ip\tcs-method\tcs(Host)\tcs-uri-stem\tcs-uri-query\tsc-status\tcs(Referer)\tcs(User-Agent)\tcs-uri-stem(truncated)\tcs-uri-query(truncated)\tx-forwarded-for\tprx-podcast-id\tprx-episode-guid\tprx-listener-id\tprx-hashed-ip";

    expect(processedContent).toContain(
      "2023-01-01\t00:00:00\tLHR50\t100\t192.168.1.0\tGET\texample.com\t/1/episode-a-guid/arr1/file.mp3\t-\t200\t-\tMozilla/5.0\t/1/episode-a-guid/arr1/file.mp3\t-\t\t1\tepisode-a-guid\t-Pj6PYJeOZ1h_EH5jb8cs0y9pxEp8Of7eYFbKft-tZg\tKaj0H2F2A0BCEFtyH98LDt8kh5O1u3COesaUC285ZXE",
    );

    expect(processedContent).toContain(expectedHeader);
    expect(processedContent).toContain("1\tepisode-a-guid");
    // Ensure that only the matching podcast ID is present
    expect(processedContent).not.toContain("2\tepisode-b-guid");
    expect(processedContent).not.toContain("3\tepisode-c-guid");
  });

  test("should handle multiple configurations", async () => {
    const mockConfig1 = {
      PODCAST_IDS: [1],
      IGNORE_PATHS: [],
      SECRET_KEY: "secret1",
      DESTINATION_BUCKET: ["dest-bucket-1"],
      DESTINATION_PREFIX: "prefix1",
    };
    const mockConfig2 = {
      PODCAST_IDS: [2],
      IGNORE_PATHS: [],
      SECRET_KEY: "secret2",
      DESTINATION_BUCKET: ["dest-bucket-2"],
      DESTINATION_PREFIX: "prefix2",
    };

    const combinedConfigs = [mockConfig1, mockConfig2];
    const configBuffer = Buffer.from(JSON.stringify(combinedConfigs), "utf-8");

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "test-config-bucket",
        Key: "test-config.json",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([configBuffer])),
      });

    const mockLogContent = `
#Version: 1.0
#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem cs-uri-query sc-status cs(Referer) cs(User-Agent) cs-uri-stem(truncated) cs-uri-query(truncated) x-forwarded-for
2023-01-01\t00:00:00\tLHR50\t100\t192.168.1.1\tGET\texample.com\t/1/episode-a-guid/arr1/file.mp3\t-\t200\t-\tMozilla/5.0\t/1/episode-a-guid/arr1/file.mp3\t-\t-
2023-01-01\t00:00:00\tLHR50\t100\t192.168.1.2\tGET\texample.com\t/2/episode-b-guid/arr2/file.mp3\t-\t200\t-\tMozilla/5.0\t/2/episode-b-guid/arr2/file.mp3\t-\t-`;
    const gzippedLogBuffer = await gzip(
      new Uint8Array(Buffer.from(mockLogContent, "utf-8")),
    );

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "source-bucket",
        Key: "logs/test-log.gz",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([gzippedLogBuffer])),
      });

    const s3Event = {
      Records: [
        {
          s3: {
            bucket: { name: "source-bucket" },
            object: { key: "logs/test-log.gz" },
          },
        },
      ],
    };

    await handler(s3Event);

    // Expect PutObjectCommand to be called twice (once for each config)
    expect(
      s3Mock.calls().filter((call) => call.args[0] instanceof PutObjectCommand)
        .length,
    ).toBe(2);

    const putCalls = s3Mock
      .calls()
      .filter((call) => call.args[0] instanceof PutObjectCommand);

    // Verify first put call (config1)
    expect(putCalls[0].args[0].input.Bucket).toBe("dest-bucket-1");
    expect(putCalls[0].args[0].input.Key).toBe("prefix1/test-log.gz");
    const processedBuffer1 = putCalls[0].args[0].input.Body;
    const gunzippedProcessed1 = await gunzip(processedBuffer1);
    const processedContent1 = gunzippedProcessed1.toString("utf-8");
    expect(processedContent1).toContain("1\tepisode-a-guid");
    expect(processedContent1).not.toContain("2\tepisode-b-guid");

    // Verify second put call (config2)
    expect(putCalls[1].args[0].input.Bucket).toBe("dest-bucket-2");
    expect(putCalls[1].args[0].input.Key).toBe("prefix2/test-log.gz");
    const processedBuffer2 = putCalls[1].args[0].input.Body;
    const gunzippedProcessed2 = await gunzip(processedBuffer2);
    const processedContent2 = gunzippedProcessed2.toString("utf-8");
    expect(processedContent2).toContain("2\tepisode-b-guid");
    expect(processedContent2).not.toContain("1\tepisode-a-guid");
  });

  test("should handle logs with IPV6 addresses", async () => {
    const mockConfig = [
      {
        PODCAST_IDS: [1],
        IGNORE_PATHS: [],
        SECRET_KEY: "test-secret",
        DESTINATION_BUCKET: ["destination-bucket-ipv6"],
        DESTINATION_PREFIX: "processed-ipv6-logs",
      },
    ];
    const configBuffer = Buffer.from(JSON.stringify(mockConfig), "utf-8");

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "test-config-bucket",
        Key: "test-config.json",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([configBuffer])),
      });

    const mockLogContent = `
#Version: 1.0
#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem cs-uri-query sc-status cs(Referer) cs(User-Agent) cs-uri-stem(truncated) cs-uri-query(truncated) x-forwarded-for
2023-01-01\t00:00:00\tLHR50\t100\t2001:0db8:85a3:0000:0000:8a2e:0370:7334\tGET\texample.com\t/1/episode-d-guid/arr1/file.mp3\t-\t200\t-\tMozilla/5.0\t/1/episode-d-guid/arr1/file.mp3\t-\t-`;

    const gzippedLogBuffer = await gzip(
      new Uint8Array(Buffer.from(mockLogContent, "utf-8")),
    );

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "source-bucket",
        Key: "logs/test-ipv6-log.gz",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([gzippedLogBuffer])),
      });

    const s3Event = {
      Records: [
        {
          s3: {
            bucket: { name: "source-bucket" },
            object: { key: "logs/test-ipv6-log.gz" },
          },
        },
      ],
    };

    await handler(s3Event);

    expect(s3Mock.call(2).args[0].input.Bucket).toBe("destination-bucket-ipv6");
    expect(s3Mock.call(2).args[0].input.Key).toBe(
      "processed-ipv6-logs/test-ipv6-log.gz",
    );

    const processedBuffer = s3Mock.call(2).args[0].input.Body;
    const gunzippedProcessed = await gunzip(processedBuffer);
    const processedContent = gunzippedProcessed.toString("utf-8");

    // Expect the IPv6 address to be masked
    const expectedIpv6Regex = new RegExp(`2001:0db8:85a3:0000::`);
    expect(processedContent).toMatch(expectedIpv6Regex);
  });

  test("should handle logs with x-forwarded-for header", async () => {
    const mockConfig = [
      {
        PODCAST_IDS: [1],
        IGNORE_PATHS: [],
        SECRET_KEY: "test-secret",
        DESTINATION_BUCKET: ["destination-bucket-xff"],
        DESTINATION_PREFIX: "processed-xff-logs",
      },
    ];
    const configBuffer = Buffer.from(JSON.stringify(mockConfig), "utf-8");

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "test-config-bucket",
        Key: "test-config.json",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([configBuffer])),
      });

    const mockLogContent = `
#Version: 1.0
#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem cs-uri-query sc-status cs(Referer) cs(User-Agent) cs-uri-stem(truncated) cs-uri-query(truncated) x-forwarded-for
2023-01-01\t00:00:00\tLHR50\t100\t10.0.0.1\tGET\texample.com\t/1/episode-e-guid/arr1/file.mp3\t-\t200\t-\tMozilla/5.0\t/1/episode-e-guid/arr1/file.mp3\t-\t203.0.113.4, 198.51.100.1`;
    const gzippedLogBuffer = await gzip(
      new Uint8Array(Buffer.from(mockLogContent, "utf-8")),
    );

    s3Mock
      .on(GetObjectCommand, {
        Bucket: "source-bucket",
        Key: "logs/test-xff-log.gz",
      })
      .resolves({
        Body: sdkStreamMixin(Readable.from([gzippedLogBuffer])),
      });

    const s3Event = {
      Records: [
        {
          s3: {
            bucket: { name: "source-bucket" },
            object: { key: "logs/test-xff-log.gz" },
          },
        },
      ],
    };

    await handler(s3Event);

    expect(s3Mock.call(2).args[0].input.Bucket).toBe("destination-bucket-xff");
    expect(s3Mock.call(2).args[0].input.Key).toBe(
      "processed-xff-logs/test-xff-log.gz",
    );

    const processedBuffer = s3Mock.call(2).args[0].input.Body;
    const gunzippedProcessed = await gunzip(processedBuffer);
    const processedContent = gunzippedProcessed.toString("utf-8");

    // Expect the first IP in x-forwarded-for to be used for hashing and c-ip to be masked
    const expectedXffRegex = new RegExp(`10\.0\.0\.0`); // c-ip masked
    const expectedXffMaskedRegex = new RegExp(
      `203\.0\.113\.0, 198\.51\.100\.0`,
    ); // x-forwarded-for masked

    processedContent.split("\n").forEach((line) => {
      // Check if prx-listener-id and prx-hashed-ip are present, as they depend on findIp and hashValue
      if (line.includes("x-edge-location")) {
        expect(line).toMatch(/prx-listener-id.*prx-hashed-ip/);
      }
      // prx-listener-id and prx-hashed-ip should not be empty
      if (line.includes("episode-e-guid")) {
        expect(line).toMatch(/\t.+\t.+$/);
        expect(line).toMatch(expectedXffRegex);
        expect(line).toMatch(expectedXffMaskedRegex);
      }
    });
  });
});
