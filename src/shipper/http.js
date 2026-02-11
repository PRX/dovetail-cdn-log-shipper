import log from "lambda-log";

// keep a memoized copy of the config in memory, JUST IN CASE!
let _config = null;
export function clearCache() {
  _config = null;
}

/**
 * Try really hard to get the config url
 */
export async function getConfig(timeouts = [1000, 2000, 5000]) {
  const opts = { signal: AbortSignal.timeout(timeouts.shift()) };
  const url = process.env.CONFIG_URL;

  try {
    const res = await fetch(url, opts);
    if (res.status === 200) {
      const cfg = await res.json();
      if (Array.isArray(cfg)) {
        _config = cfg;
        return _config;
      } else {
        log.warn(`getConfig non-array from ${url}`);
      }
    } else {
      log.warn(`getConfig ${res.status} from ${url}`);
    }
  } catch (err) {
    log.error(`getConfig error from ${url}: ${err.message}`, { error: err });
  }

  if (timeouts.length) {
    return getConfig(timeouts);
  } else if (_config) {
    log.warn("getConfig using cached");
    return _config;
  } else {
    throw new Error("Unable to getConfig");
  }
}
