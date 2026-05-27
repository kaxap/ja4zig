# ja4zig

Zig port of the FoxIO JA4+ network fingerprinting suite.
Mirrors the Rust crate at [`../ja4/rust/ja4`](../ja4/rust/ja4).
Targets Zig 0.16.0.

> **Status:** phase 1 — test harness only. The CLI is a stub; the snapshot
> tests intentionally fail until protocol modules land.

## Layout

```
src/             ja4 CLI and library modules (incremental ports of rust/ja4/src/*.rs)
tests/
  snapshot_test.zig          invokes the built ja4 binary against every pcap and diffs the output
  testdata/
    pcap/<name>.pcap[ng]     upstream pcap fixtures (vendored — repo is self-contained)
    snapshots/<name>.yaml    expected output (vendored from rust/ja4/src/snapshots)
  import-snapshots.sh        regenerates the YAML fixtures from an upstream checkout
config.toml      bundled default config (copied from rust/ja4/config.toml)
```

## Build & test

```sh
zig build                # produces zig-out/bin/ja4
zig build test           # runs unit tests + snapshot harness
zig build run -- <pcap>  # run the CLI
```

In phase 1 the unit tests for `hash12` and the tshark-version parser pass; the
37 snapshot fixtures fail uniformly with `ja4zig: not implemented yet`.

## Regenerating snapshot fixtures

The pcap and YAML fixtures under `tests/testdata/` are vendored — the repo
needs no external checkout to build or test. To refresh the YAML snapshots
against a newer upstream:

```sh
JA4_UPSTREAM=/path/to/FoxIO-LLC/ja4 ./tests/import-snapshots.sh
```

(`JA4_UPSTREAM` defaults to `../../ja4` relative to this repo.) The
`gtp-iphone.pcap` snapshot is skipped because its pcap is not bundled
upstream.
