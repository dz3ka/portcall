/**
 * The PAC helper library, as source text that runs *inside* the sandbox.
 *
 * This file exports one string and imports nothing. That is the whole point:
 * every value a PAC script can touch has to be created by the sandbox realm
 * itself. The previous shape put the eight helpers on the sandbox as host
 * function objects, and a host function object is a live handle back into
 * this realm - `dnsResolve.constructor("return process")()` reached the real
 * `process`, read `process.env` and wrote a file, because
 * `codeGeneration: { strings: false }` is a *per-context* flag and the
 * `Function` reached through a host object's prototype chain belongs to the
 * host context, where code generation is allowed. `Object.freeze` does not
 * help; freezing a function does not remove its inherited `.constructor`.
 *
 * So: no object crosses the boundary in either direction (see `pac.ts`).
 * Four strings go in on the context global, this script reads them, deletes
 * the slots and defines the helpers as ordinary functions of the sandbox
 * realm. The verdict comes back out as a string completion value.
 *
 * Two consequences of running in-context, both accepted deliberately:
 *
 * - The helpers close over `JSON.parse`d data and use the sandbox's own
 *   intrinsics, so a hostile script that monkey-patches, say,
 *   `String.prototype.toLowerCase` before calling `shExpMatch` can change
 *   what its own helpers answer. It cannot learn anything it did not already
 *   have: the only host-derived data in the realm is the request URL/host,
 *   the one pre-resolved target and `myIpAddress()`, all of which the helpers
 *   hand out on request anyway. Self-inflicted wrong routing is not a
 *   security property this tool promises.
 * - `PAC_BOOTSTRAP_SOURCE` is a constant: nothing is interpolated into its
 *   source text, so no per-call value can ever be smuggled in as code.
 *
 * The semantics below are a verbatim port of the previous host-side helpers
 * and are pinned by `test/proxy-pac.test.ts` - the lenient dotted-quad parse
 * (`Number('') === 0`), `shExpMatch`'s exact escape set, `dnsResolve`
 * answering `addresses[0] ?? null`, and above all ADR-0012: `dnsResolve` /
 * `isResolvable` / `isInNet` answer only for the one host the impure shell
 * already resolved, and never perform a lookup of their own.
 */
export const PAC_BOOTSTRAP_SOURCE = `'use strict';
(function bootstrap(g) {
  var url = g.__pacUrl;
  var host = g.__pacHost;
  var targetJson = g.__pacTargetJson;
  var myAddress = g.__pacMyAddress;

  // The handoff slots exist only for the length of this function: the
  // untrusted script that runs next must not find them on the global.
  delete g.__pacUrl;
  delete g.__pacHost;
  delete g.__pacTargetJson;
  delete g.__pacMyAddress;

  // Parsed here, in this realm, so the host never hands an object across.
  // 'null' is what the host seeds when nothing was pre-resolved.
  var target = JSON.parse(targetJson);

  function matchesTarget(candidate) {
    return target !== null && candidate.toLowerCase() === target.host.toLowerCase();
  }

  function literalIpv4(text) {
    var parts = text.split('.');
    if (parts.length !== 4) return null;
    var octets = parts.map(function (part) { return Number(part); });
    var bad = octets.some(function (n) { return !Number.isInteger(n) || n < 0 || n > 255; });
    if (bad) return null;
    return { a: octets[0], b: octets[1], c: octets[2], d: octets[3] };
  }

  function resolvedIpv4(candidate) {
    if (target === null || !matchesTarget(candidate)) return null;
    for (var i = 0; i < target.addresses.length; i += 1) {
      var parsed = literalIpv4(target.addresses[i]);
      if (parsed !== null) return parsed;
    }
    return null;
  }

  function dnsResolve(candidate) {
    if (typeof candidate !== 'string' || target === null || !matchesTarget(candidate)) return null;
    return target.addresses[0] ?? null;
  }

  function isResolvable(candidate) {
    return dnsResolve(candidate) !== null;
  }

  function isInNet(candidate, pattern, mask) {
    if (typeof candidate !== 'string' || typeof pattern !== 'string' || typeof mask !== 'string') return false;
    var ip = literalIpv4(candidate);
    if (ip === null) ip = resolvedIpv4(candidate);
    var patternIp = literalIpv4(pattern);
    var maskIp = literalIpv4(mask);
    if (ip === null || patternIp === null || maskIp === null) return false;
    return (
      (ip.a & maskIp.a) === (patternIp.a & maskIp.a) &&
      (ip.b & maskIp.b) === (patternIp.b & maskIp.b) &&
      (ip.c & maskIp.c) === (patternIp.c & maskIp.c) &&
      (ip.d & maskIp.d) === (patternIp.d & maskIp.d)
    );
  }

  function myIpAddress() {
    return myAddress;
  }

  function isPlainHostName(candidate) {
    return typeof candidate === 'string' && !candidate.includes('.') && !candidate.includes(':');
  }

  function dnsDomainIs(candidate, domain) {
    if (typeof candidate !== 'string' || typeof domain !== 'string') return false;
    return candidate.length >= domain.length && candidate.slice(candidate.length - domain.length) === domain;
  }

  function localHostOrDomainIs(candidate, fullyQualified) {
    if (typeof candidate !== 'string' || typeof fullyQualified !== 'string') return false;
    if (candidate === fullyQualified) return true;
    var dot = fullyQualified.indexOf('.');
    return dot !== -1 && candidate === fullyQualified.slice(0, dot);
  }

  function shExpMatch(candidate, pattern) {
    if (typeof candidate !== 'string' || typeof pattern !== 'string') return false;
    var escaped = pattern.replace(/[.+^\${}()|[\\]\\\\]/g, '\\\\$&').replace(/\\*/g, '.*').replace(/\\?/g, '.');
    return new RegExp('^' + escaped + '$').test(candidate);
  }

  g.dnsResolve = dnsResolve;
  g.isResolvable = isResolvable;
  g.isInNet = isInNet;
  g.myIpAddress = myIpAddress;
  g.isPlainHostName = isPlainHostName;
  g.dnsDomainIs = dnsDomainIs;
  g.localHostOrDomainIs = localHostOrDomainIs;
  g.shExpMatch = shExpMatch;

  // The one thing the trailer appended to the untrusted script calls.
  // 'FindProxyForURL' is resolved here, at call time, against the global the
  // untrusted script declared it on; a script that never declares it throws a
  // ReferenceError, which 'evaluatePac' reports as 'error'.
  g.__pacRun = function __pacRun() {
    var r = FindProxyForURL(url, host);
    return typeof r === 'string' ? r : null;
  };
})(globalThis);
`;
