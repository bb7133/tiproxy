# Native capture format oracle

`main.go` writes five deterministic records through the production Go
`pkg/sqlreplay/cmd.NativeEncoder`. Regenerate and verify the checked-in binary
fixture from the repository root:

```sh
go run ./tests/dataplane/capture-format > tests/dataplane/capture-format/native-v1.log
go run ./tests/dataplane/capture-format | cmp - tests/dataplane/capture-format/native-v1.log
```

The fixture covers a nanosecond timestamp with a non-hour offset, default
Query, explicit command types, false success, prepared statement metadata with
Unicode and Go escapes, binary Execute payload, and an embedded newline in a
Query body. Rust `dataplane::capture_format` decodes each record and requires
byte-identical re-encoding, including the binary body and trailing newline.

This format slice does not start capture or replay. It preserves the original
Go quoted prepared statement literal instead of parsing it, and requires a
future producer to apply the existing Go capture safety filters before passing
any payload to the codec. The current Rust capture configuration and admin
routes remain disabled.
