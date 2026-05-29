# ja4zig

Zig port of the FoxIO JA4+ network fingerprinting suite.
Mirrors the Rust crate at [`https://github.com/FoxIO-LLC/ja4`](https://github.com/FoxIO-LLC/ja4).
Targets Zig 0.16.0.

| Surface | State |
|---|---|
| Library helpers (`hash`, `tshark`) | usable — see [Public API](#public-api) |
| `ja4` CLI binary | stub — exits with `ja4zig: not implemented yet` |
| Snapshot suite | 37 fixtures, all currently failing against the stub (by design) |
| Unit tests | 14 passing (hash + cache + tshark version + stats) |

The full per-protocol fingerprint pipeline (JA4 / JA4S / JA4H / JA4L / JA4X / JA4SSH) is in progress — see [Roadmap](#roadmap).

## What works today

- **`hash.hash12(s, &out)`** — SHA-256 truncation, hex-encoded first 6 bytes. The primitive that every JA4 family hash ends in. Thread-local memoization makes the workload-typical "same fingerprint string repeated many times" case essentially free.
- **`tshark.parseVersion(line)`** — pulls a SemVer string out of `tshark --version`'s first line; used to gate JA4+ against the >=4.0.6 floor that upstream requires.
- **Vendored fixture corpus** — 38 pcaps + 37 reference YAML snapshots from upstream Rust `insta`, plus an opinionated benchmark suite. Even if you never call the Zig library, the harness is a usable template for any tshark-driven project.

## What's still WIP

- Per-protocol fingerprint modules — TLS (JA4/JA4S), HTTP (JA4H), SSH (JA4SSH), latency (JA4L), X.509 (JA4X).
- The `ja4` CLI binary exits non-zero with `ja4zig: not implemented yet` so the snapshot harness has something to invoke. See [Roadmap](#roadmap) for the order modules will land.

## Using ja4zig as a dependency

Until ja4zig ships a tagged release, depend on it by relative path. From your project's `build.zig.zon`:

```zig
.dependencies = .{
    .ja4zig = .{
        .path = "../ja4zig", // adjust to wherever you checked it out
    },
},
```

Then in your `build.zig`:

```zig
const ja4zig = b.dependency("ja4zig", .{
    .target = target,
});
exe.root_module.addImport("ja4zig", ja4zig.module("ja4zig"));
```

And call from your code:

```zig
const ja4zig = @import("ja4zig");

pub fn main() void {
    var digest: [12]u8 = undefined;
    ja4zig.hash.hash12("t13d1715h2_5b234860e130_014157ec0da2", &digest);
    std.debug.print("ja4 = {s}\n", .{&digest});
}
```

Once a remote release is published, the relative path swaps for a `zig fetch --save <url>` invocation.

## Public API

### `hash.hash12(s: []const u8, out: *[12]u8) void`

Writes the first 12 hex characters of `SHA-256(s)` into `out`. Returns `"000000000000"` (twelve ASCII zeros) when `s.len == 0`. No allocations.

- **Thread safety**: the memoization cache is `threadlocal`. Each thread starts with a cold cache; calls on one thread never interfere with another's results.
- **Soundness**: a cache hit verifies a 160-bit content fingerprint before returning. Cache miss always falls through to the SHA-256 compress.

### `hash.resetCache() void`

Clears the threadlocal cache. Intended for test isolation when you want guaranteed cold-cache behavior; not for the hot path.

### `tshark.parseVersion(output: []const u8) ?[]const u8`

Parses the first line of `tshark --version`'s output (e.g. `"TShark (Wireshark) 4.0.8 (v4.0.8-0-g81696bb74857)."`) and returns a slice **into the input** pointing at the version digits (`"4.0.8"`). Returns `null` if:

- No `") "` marker is present.
- The marker is found but no whitespace terminator follows (we don't trust a version string that runs off the end of the buffer).

Handles a bare `)` that isn't followed by space (e.g. inside a name) by continuing to scan; strips a single trailing `.` if present.

## Design notes

### Content-keyed cache (`src/hash.zig`)

`hash12` is fronted by a 16-slot direct-mapped cache living in thread-local storage. The cache entry layout is `extern struct { head: u64, tail: u64, len: u32, _pad: u32, digest: [12]u8 }` so each slot fits cleanly in a single cache line.

The lookup key is **160 bits**: `(len, head, tail)` where `head` and `tail` are little-endian `u64` reads of the first and last 8 bytes of the input (or the whole content zero-padded into one `u64` if `s.len < 8`). The slot index is `(head ^ tail ^ len) & 15`. A cache hit returns the cached digest with no SHA-256 work, in constant time independent of input size.

**False-positive surface**: a wrong digest can only be returned if two inputs simultaneously collide on length, the first 8 bytes, and the last 8 bytes — 160 bits of identity. That's below the noise floor of any non-adversarial JA4 workload. For adversarial input, this is *not* a cryptographic guarantee; JA4 isn't an authenticator, so that's appropriate.

The empty-input short-circuit (`s.len == 0` → `"000000000000"`) sits in front of the cache, so `len == 0` doubles as the "vacant slot" sentinel — a real input can never collide with an empty slot.

### SIMD hex encoding (`encodeHex6` in `src/hash.zig`)

Six raw bytes → twelve ASCII hex characters in roughly five SIMD operations on AArch64. The implementation:

1. Splits each byte's hi/lo nibbles via `@Vector(6, u8)` shift+mask.
2. Interleaves the two 6-lane vectors into a single 12-lane vector via `@shuffle` with a negative-index mask `{0, -1, 1, -2, …}` (positive picks from `hi`, `~negative` picks from `lo`).
3. Lands each nibble in ASCII branchlessly: `n + '0' + ((n + 6) >> 4) * 0x27`. For `n in 0..=9` the shift result is 0 (lands on `'0'..'9'`); for `n in 10..=15` it's 1 (adds `0x27` to land on `'a'..'f'`).

Replaces a per-byte table-lookup loop that the previous implementation used. On AArch64 the whole tail compiles to roughly `ushr ; and ; tbl ; add ; ushr ; mla ; str`.

### Parallel snapshot harness (`tests/snapshot_test.zig`)

The snapshot test spawns up to `min(std.Thread.getCpuCount(), 8)` worker threads that pull pcap indices off a single `std.atomic.Value(usize)` counter. Each worker opens its own `Io.Dir` handle on the snapshots directory so they don't contend on a shared cursor.

Override the worker count with `SNAPSHOT_WORKERS=N` (parsed via `std.c.getenv`) — useful for measuring serial-vs-parallel scaling. The architecture only shows its win once the real CLI invokes tshark per fixture (~50 ms of startup × 37 fixtures = ~1.85 s sequential, ~250 ms with 8 workers); against the current µs-fast stub binary, both modes finish in well under a second.

## Build, test, bench

```sh
zig build                # produces zig-out/bin/ja4 and zig-out/bin/ja4zig-bench
zig build test           # 14 unit tests + 37 snapshot tests (all snapshots fail vs the stub, by design)
zig build run -- <pcap>  # run the CLI stub
zig build bench          # full bench suite (micro + per-pcap)
```

### Bench commands

```sh
zig build bench                                # full suite (defaults)
zig build bench -- micro --batches=50          # microbenchmarks only
zig build bench -- pcap --runs=5 --warmup=2    # per-pcap only, more samples
zig build bench -- all --json > out.json       # machine-readable output
zig build -Dbench-optimize=Debug bench         # build the bench binary in Debug
```

The bench binary is built in `ReleaseFast` by default. Two suites:

- **Microbenchmarks** — auto-calibrated iteration counts, `asm volatile` optimizer-defeat barriers. Covers `hash12` across four input sizes (empty / 20 B / 256 B / 4 KiB) and `parseVersion` (happy + miss). Reports min, median, mean, p95, stddev, CV, ops/s, and (where meaningful) MB/s.
- **Per-pcap end-to-end** — runs every detected JA4 implementation against every fixture and reports wall-clock distribution + throughput. Detected impls: `ja4zig` (this repo), upstream `rust/ja4` release binary (if built), upstream `python/ja4.py`, and raw `tshark -T ek` as a lower-bound baseline. Missing impls are silently skipped.

A `<1ns` entry means the body amortized below the host clock's nanosecond resolution after `iters_per_batch` got large enough; it does not mean zero work. On the reference machine `hash12/realistic_256B` reports 1 ns / ~205 GB/s after the cache warms (effectively the cache-hit floor, not raw SHA-256 throughput), and the raw `tshark` baseline takes ~55 ms on a 1 KB pcap (dominated by tshark startup).

## Layout

```
ja4zig/
├── build.zig
├── build.zig.zon
├── config.toml               (copied from rust/ja4/config.toml)
├── src/
│   ├── main.zig              (CLI entry — currently a stub)
│   ├── root.zig              (library root — re-exports hash, tshark)
│   ├── hash.zig              (hash12 + content-keyed cache + SIMD hex encoder)
│   └── tshark.zig            (parseVersion)
├── bench/
│   ├── main.zig              (bench CLI dispatcher)
│   ├── micro.zig             (microbenchmarks with calibration + asm barriers)
│   ├── pcap_bench.zig        (per-pcap end-to-end across detected impls)
│   ├── output.zig            (table + JSON formatters)
│   ├── stats.zig             (min/median/mean/p95/stddev/CV)
│   └── timer.zig             (std.Io.Clock wrapper)
└── tests/
    ├── snapshot_test.zig     (parallel pcap-vs-YAML harness)
    ├── import-snapshots.sh   (refresh YAML fixtures from upstream insta)
    └── testdata/
        ├── pcap/<name>.pcap[ng]     (vendored — 38 files, ~5.6 MB total)
        └── snapshots/<name>.yaml    (vendored — 37 reference snapshots)
```

## Regenerating snapshot fixtures

The pcap and YAML fixtures under `tests/testdata/` are vendored — the repo needs no external checkout to build or test. To refresh the YAML snapshots against a newer upstream:

```sh
JA4_UPSTREAM=/path/to/FoxIO-LLC/ja4 ./tests/import-snapshots.sh
```

(`JA4_UPSTREAM` defaults to `../../ja4` relative to this repo.) The `gtp-iphone.pcap` snapshot is skipped because its pcap isn't bundled upstream.

## Roadmap

Aligned with the Rust crate's module layout. Each phase makes more snapshot fixtures pass:

- **Phase 2** — tshark subprocess driver + `Packet` / `Proto` abstractions. We'll use `tshark -T ek` (NDJSON, parseable incrementally with `std.json.Scanner`) rather than PDML/XML.
- **Phase 3** — per-protocol modules in dependency order: `tcp` → `stream` → `tls` (JA4/JA4S) → `http` (JA4H) → `ssh` (JA4SSH) → `time` (JA4L) → `ja4x` (X.509).
- **Phase 4** — CLI flag parity with `rust/ja4`: `-j/--json`, `-o/--output`, `-r/--with-raw`, `-O/--original-order`, `--keylog-file`, `-n/--with-packet-numbers`.

## License & attribution

This is an independent Zig re-implementation of the upstream FoxIO JA4+ algorithms. It is not affiliated with FoxIO, LLC.

The upstream licenses apply to the algorithms this port implements:

- **JA4** (TLS client fingerprinting) is BSD 3-Clause — see [upstream `LICENSE-JA4`](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4). Free for commercial use.
- **JA4+** extensions — JA4S, JA4H, JA4L, JA4X, JA4SSH (and others) — are licensed under [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE), which is **non-commercial only**. If your use of this port enables the JA4+ extensions, you must comply with that license.

See upstream's [License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) for the FoxIO License 1.1's intent and edge cases.
