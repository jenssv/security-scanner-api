// SSRF protection.
//
// Users give this API a URL, and the server fetches it. Without protection,
// someone could ask it to fetch addresses that are only reachable from inside
// the server, such as:
//   http://127.0.0.1:6379             -> a local database
//   http://169.254.169.254/latest/... -> the AWS metadata service, which can
//                                        leak the server's AWS credentials
//                                        (the 2019 Capital One breach)
//
// The defence has two parts:
//   1. parseTarget() only accepts plain http/https URLs on default ports.
//   2. safeLookup() is used for every DNS lookup the scanner makes. It rejects
//      any hostname that resolves to a private or reserved IP. Because the
//      check runs at connection time, it also covers redirects and
//      "DNS rebinding" tricks.

import dns from 'node:dns';
import { BlockList, isIP } from 'node:net';

export class BlockedTargetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BlockedTargetError';
  }
}

const blocked = new BlockList();

const IPV4_RANGES = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (includes AWS metadata 169.254.169.254)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
];

const IPV6_RANGES = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  // IPv4-mapped addresses (::ffff:10.0.0.1) are NOT listed here: BlockList
  // already checks them against the IPv4 ranges above, and adding
  // ::ffff:0:0/96 would make it block every IPv4 address.
  ['64:ff9b::', 96], // NAT64 (could hide a private IPv4)
  ['100::', 64], // discard
  ['2001:db8::', 32], // documentation
  ['fc00::', 7], // unique local (private)
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

for (const [addr, prefix] of IPV4_RANGES) blocked.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of IPV6_RANGES) blocked.addSubnet(addr, prefix, 'ipv6');

export function isBlockedIp(address) {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, 'ipv4');
  if (family === 6) return blocked.check(address, 'ipv6');
  return true; // not a valid IP -> refuse
}

/**
 * Drop-in replacement for dns.lookup, passed as the `lookup` option to
 * http/https/tls. Refuses hostnames that resolve to any blocked address.
 */
export function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (typeof options === 'number') options = { family: options };

  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);

    if (addresses.length === 0 || addresses.some((a) => isBlockedIp(a.address))) {
      return callback(
        new BlockedTargetError(`Refusing to scan ${hostname}: it resolves to a private or reserved IP address`),
      );
    }

    if (options.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

/**
 * Turns user input ("example.com", "https://example.com/page") into a URL,
 * or throws if it isn't something we're willing to scan.
 */
export function parseTarget(input) {
  let raw = String(input ?? '').trim();
  if (!raw) throw new BlockedTargetError('Missing url');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new BlockedTargetError('That is not a valid URL');
  }

  assertSafeUrl(url);
  return url;
}

/** Rules every URL must follow, including redirect targets. */
export function assertSafeUrl(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BlockedTargetError('Only http and https URLs can be scanned');
  }
  if (url.username || url.password) {
    throw new BlockedTargetError('URLs with usernames or passwords are not allowed');
  }
  // Only default ports (80/443), so the scanner can't be used to probe
  // arbitrary ports on other people's servers.
  if (url.port !== '') {
    throw new BlockedTargetError('Custom ports are not allowed; use the default http/https port');
  }
  if (!url.hostname || url.hostname.length > 253) {
    throw new BlockedTargetError('Invalid hostname');
  }
  // Node skips the DNS lookup (and so safeLookup) when the host is already
  // an IP address, so raw IPs have to be checked here.
  assertSafeHost(url.hostname);
}

/** Rejects a hostname that is a raw private/reserved IP address. */
export function assertSafeHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, ''); // IPv6 literals come as [::1]
  if (isIP(host) && isBlockedIp(host)) {
    throw new BlockedTargetError(`Refusing to scan ${host}: it is a private or reserved IP address`);
  }
}
