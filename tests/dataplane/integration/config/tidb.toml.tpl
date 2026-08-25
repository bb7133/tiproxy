# Generated for the TiProxy dataplane integration topology. Do not use in production.

[security]
ssl-ca = "@CA_CERT@"
ssl-cert = "@SERVER_CERT@"
ssl-key = "@SERVER_KEY@"
tls-version = "TLSv1.2"

[proxy-protocol]
networks = "@PROXY_NETWORKS@"
fallbackable = @PROXY_FALLBACKABLE@
