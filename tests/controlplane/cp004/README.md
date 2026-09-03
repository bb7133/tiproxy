# CP-CFG/NS evidence

`run.sh` exercises the production Go and Rust configuration owners rather than
standalone duplicate parsers.

It proves:

- byte-identical canonical TOML for default, partial, and every-field inputs;
- byte-identical, name-sorted legacy namespace JSON;
- a skipped-field mutation is detected;
- real embedded-etcd bootstrap, persistent owner-fenced writes, invalid
  last-good retention, contiguous generations, acknowledgement-after-source
  publication for back-to-back namespace mutations, namespace immutability,
  election loss/recovery, restart, compaction, and relist recovery;
- mutations for a generation skip, invalid overwrite, lease-attached config
  key, and revoked-owner write all fail.

Run it from the repository root:

```sh
make controlplane-cp004-evidence
```

The Go fixture is the restartable embedded-etcd process from CP-ETCD. Each
live or mutation row receives an isolated data directory and is force-cleaned
by the harness trap.
