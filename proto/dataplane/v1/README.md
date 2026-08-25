# Control protocol v1 code generation

`control.proto` is the only source schema. Generated Go and Rust sources plus
both cross-language golden frames are committed, so ordinary builds use no
network and do not require Buf or protobuf generators.

Run:

```sh
make control-proto-generate-check
```

The explicit regeneration command installs only these pinned tools into the
ignored repository `bin/` directory:

- Buf `v1.72.0`
- `protoc-gen-go` `v1.36.11`
- `protoc-gen-prost` `0.5.0`

It then lints the schema, regenerates both languages, rewrites the Go-to-Rust
and Rust-to-Go golden frames, and fails if the checked-in output differs. The
Rust dependency graph is pinned by `rust/Cargo.lock`.
