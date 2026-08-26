function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, ".internal.example.com")) {
    return "DIRECT";
  }
  if (shExpMatch(host, "*.example.com")) {
    return "PROXY proxy.corp.internal:8080";
  }
  return "PROXY fallback.corp.internal:3128";
}
