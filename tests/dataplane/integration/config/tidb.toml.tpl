# Generated for the TiProxy dataplane integration topology. Do not use in production.

[security]
ssl-ca = "@CA_CERT@"
ssl-cert = "@SERVER_CERT@"
ssl-key = "@SERVER_KEY@"
tls-version = "TLSv1.2"
# Session-token signing material: WITHOUT it every backend reports
# support_redirection=false and the router never balances - the
# keyspace-guard phase would be fake pressure. The same pair is shared
# by all backends across BOTH clusters.
session-token-signing-cert = "@SESSION_TOKEN_CERT@"
session-token-signing-key = "@SESSION_TOKEN_KEY@"

[proxy-protocol]
networks = "@PROXY_NETWORKS@"
fallbackable = @PROXY_FALLBACKABLE@
