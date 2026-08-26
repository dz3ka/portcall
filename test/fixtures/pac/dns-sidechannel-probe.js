function FindProxyForURL(url, host) {
  // Attempts to use dnsResolve as a side channel to probe a hostname that is
  // NOT the pre-resolved target. Must come back null - never a real lookup.
  var probed = dnsResolve("somehost.internal");
  if (probed === null) {
    return "PROXY blocked-sidechannel:1";
  }
  return "PROXY leaked:" + probed;
}
