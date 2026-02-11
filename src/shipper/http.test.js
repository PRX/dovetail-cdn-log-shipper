import { jest } from "@jest/globals";
import log from "lambda-log";
import nock from "nock";
import { clearCache, getConfig } from "./http.js";

describe("http", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.CONFIG_URL = "http://my.config/destinations.json";
    clearCache();
  });

  describe("#getConfig", () => {
    const host = "http://my.config";
    const path = "/destinations.json";

    it("fetches and parses config", async () => {
      const s1 = nock(host).get(path).reply(200, '[{"some":"config"}]');
      expect(await getConfig()).toEqual([{ some: "config" }]);
      expect(s1.isDone()).toEqual(true);
    });

    it("retries errors", async () => {
      const s1 = nock(host).get(path).reply(404);
      const s2 = nock(host).get(path).reply(500);
      const s3 = nock(host).get(path).reply(200, '[{"some":"config"}]');
      const spy = jest.spyOn(log, "warn").mockImplementation();

      expect(await getConfig()).toEqual([{ some: "config" }]);

      expect(s1.isDone()).toEqual(true);
      expect(s2.isDone()).toEqual(true);
      expect(s3.isDone()).toEqual(true);

      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.mock.calls[0][0]).toMatch("getConfig 404");
      expect(spy.mock.calls[1][0]).toMatch("getConfig 500");
    });

    it("retries timeouts", async () => {
      const s1 = nock(host).get(path).delay(10).reply(200, '[{"c":"1"}]');
      const s2 = nock(host).get(path).delay(10).reply(200, '[{"c":"2"}]');
      const s3 = nock(host).get(path).delay(10).reply(200, '[{"c":"3"}]');
      const s4 = nock(host).get(path).reply(200, '[{"c":"4"}]');
      const spy = jest.spyOn(log, "error").mockImplementation();

      expect(await getConfig([1, 1, 1, 100])).toEqual([{ c: "4" }]);
      expect(s1.isDone()).toEqual(true);
      expect(s2.isDone()).toEqual(true);
      expect(s3.isDone()).toEqual(true);
      expect(s4.isDone()).toEqual(true);

      expect(spy).toHaveBeenCalledTimes(3);
      expect(spy.mock.calls[0][0]).toMatch("aborted due to timeout");
      expect(spy.mock.calls[1][0]).toMatch("aborted due to timeout");
      expect(spy.mock.calls[2][0]).toMatch("aborted due to timeout");
    });

    it("handles json decode errors", async () => {
      const s1 = nock(host).get(path).delay(10).reply(200, "not { json");
      const s2 = nock(host)
        .get(path)
        .delay(10)
        .reply(200, '[{"some":"config"}]');
      const spy = jest.spyOn(log, "error").mockImplementation();

      expect(await getConfig()).toEqual([{ some: "config" }]);
      expect(s1.isDone()).toEqual(true);
      expect(s2.isDone()).toEqual(true);

      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][0]).toMatch("is not valid JSON");
    });

    it("checks for arrays", async () => {
      const s1 = nock(host).get(path).delay(10).reply(200, '"not-an-array"');
      const s2 = nock(host)
        .get(path)
        .delay(10)
        .reply(200, '[{"some":"config"}]');
      const spy = jest.spyOn(log, "warn").mockImplementation();

      expect(await getConfig()).toEqual([{ some: "config" }]);
      expect(s1.isDone()).toEqual(true);
      expect(s2.isDone()).toEqual(true);

      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][0]).toMatch("getConfig non-array");
    });

    it("uses cached values", async () => {
      const s1 = nock(host).get(path).reply(200, '[{"c":"1"}]');
      expect(await getConfig()).toEqual([{ c: "1" }]);
      expect(s1.isDone()).toEqual(true);

      const s2 = nock(host).get(path).reply(500);
      const s3 = nock(host).get(path).reply(500);
      const spy = jest.spyOn(log, "warn").mockImplementation();

      expect(await getConfig([100, 100])).toEqual([{ c: "1" }]);
      expect(s2.isDone()).toEqual(true);
      expect(s3.isDone()).toEqual(true);

      expect(spy).toHaveBeenCalledTimes(3);
      expect(spy.mock.calls[0][0]).toMatch("getConfig 500");
      expect(spy.mock.calls[1][0]).toMatch("getConfig 500");
      expect(spy.mock.calls[2][0]).toMatch("getConfig using cached");
    });

    it("throws errors if it can't get any config", async () => {
      const s1 = nock(host).get(path).reply(500);
      const s2 = nock(host).get(path).reply(500);
      const spy = jest.spyOn(log, "warn").mockImplementation();

      await expect(getConfig([100, 100])).rejects.toThrow(
        /Unable to getConfig/,
      );
      expect(s1.isDone()).toEqual(true);
      expect(s2.isDone()).toEqual(true);

      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.mock.calls[0][0]).toMatch("getConfig 500");
      expect(spy.mock.calls[1][0]).toMatch("getConfig 500");
    });
  });
});
