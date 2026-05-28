# ja4zig

Zig port of the FoxIO JA4+ network fingerprinting suite.
Mirrors the Rust crate at [`https://github.com/FoxIO-LLC/ja4`](https://github.com/FoxIO-LLC/ja4).
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

## Benchmarks

```sh
zig build bench                                # full suite (micro + per-pcap, defaults)
zig build bench -- micro --batches=50          # microbenchmarks only
zig build bench -- pcap --runs=5 --warmup=2    # per-pcap only, more samples
zig build bench -- all --json > out.json       # machine-readable output
```

Two layers:

- **Microbenchmarks** — auto-calibrated iteration counts, configurable batch
  count, optimizer-defeat barrier via `asm volatile`. Currently covers
  `hash12` across four input sizes (empty / 20 B / 256 B / 4 KiB) and
  `parseVersion` (happy + miss paths). Reports min, median, mean, p95,
  stddev, coefficient of variation, ops/s, and (where meaningful) MB/s.
- **Per-pcap end-to-end** — runs every detected JA4 implementation against
  every fixture in `tests/testdata/pcap/` and reports wall-clock distribution
  + throughput. Detected impls: `ja4zig` (this repo), upstream `rust/ja4`
  release binary (if built), upstream `python/ja4.py`, and raw `tshark -T ek`
  as a lower-bound baseline. Missing impls are silently skipped, so the
  bench works without a Rust toolchain.

The benchmark binary is built in `ReleaseFast` by default (override with
`-Dbench-optimize=Debug` etc.). On this machine, `hash12/realistic_256B`
clocks in around 70 ns / 3 GB/s; the tshark baseline takes ~55 ms on a
1 KB pcap (dominated by tshark startup).

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
