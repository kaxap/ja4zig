//! ja4zig — Zig port of the FoxIO JA4+ Rust crate (`rust/ja4`).
//!
//! Modules are added incrementally. Phase 1 only exposes the helpers that the
//! unit tests in `tests/unit/` exercise.

pub const hash = @import("hash.zig");
pub const tshark = @import("tshark.zig");

test {
    // Pull in unit tests from imported modules.
    _ = hash;
    _ = tshark;
}
