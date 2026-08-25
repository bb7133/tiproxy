# Parity no-impact declarations

Add a JSON file matching `schema.json` only when a monitored production Go
change cannot affect observable dataplane behavior. Generate the exact semantic
hashes with the drift checker's `-mode hashes` output. The reason must discuss
MySQL packets/session state, configuration/reload behavior, routing, metrics,
and error classification as applicable.

The `owner` and `review_url` must identify the approving code owner and the
specific GitHub review. Branch protection must require CODEOWNERS approval; the
offline checker validates the declaration shape and exact hashes but cannot
authenticate GitHub review state.
