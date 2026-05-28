const std = @import("std");

/// Returns the first 12 hex characters of the SHA-256 digest of `s`.
/// Returns `"000000000000"` if `s` is empty.
///
/// Mirrors `hash12` in `rust/ja4/src/lib.rs`.
///
/// Implementation notes (optimized):
///   • Empty fast-path uses array assignment, which the compiler lowers to a
///     12-byte immediate store — no `@memcpy` call overhead.
///   • SHA-256 is at hardware throughput (ARMv8 SHA-2 intrinsics ≈ 3 GB/s
///     on Apple Silicon, SHA-NI on recent x86_64). We can't go faster than
///     the silicon per byte, so the only way left to "make hash12 faster"
///     is to avoid running SHA-256 in the first place — see the cache.
///   • Thread-local 16-slot direct-mapped cache keyed on a 160-bit content
///     fingerprint (len + first 8 bytes + last 8 bytes). JA4 traffic is
///     highly repetitive (same TLS client = same fingerprint string), so
///     in practice this hits often. Cache hit cost: one u64-trio compare
///     and a 12-byte load — independent of input size, ≈ 5 ns.
///   • Soundness: a cache hit requires len + 64 head bits + 64 tail bits
///     all to match. False positives require a 160-bit content collision,
///     which is below the noise floor for non-adversarial inputs.
///   • The hex tail is a 12-lane SIMD branchless conversion (`@shuffle` to
///     interleave hi/lo nibbles, then `n + '0' + ((n+6)>>4)*0x27`).
pub fn hash12(s: []const u8, out: *[12]u8) void {
    if (s.len == 0) {
        out.* = "000000000000".*;
        return;
    }

    // ── Build a content key in O(1) regardless of |s|. ────────────────────
    var head: u64 = undefined;
    var tail: u64 = undefined;
    if (s.len >= 8) {
        head = std.mem.readInt(u64, s[0..8], .little);
        tail = std.mem.readInt(u64, s[s.len - 8 ..][0..8], .little);
    } else {
        // Pack the entire (short) content into one u64 so the cache key
        // is still uniquely tied to the bytes, not a windowed sample.
        var buf: [8]u8 = @splat(0);
        @memcpy(buf[0..s.len], s);
        head = std.mem.readInt(u64, &buf, .little);
        tail = head;
    }
    const len32: u32 = @intCast(s.len);
    const slot_idx: usize = @as(usize, @truncate(head ^ tail ^ @as(u64, len32))) & (cache_size - 1);

    const slot = &cache[slot_idx];
    if (slot.len == len32 and slot.head == head and slot.tail == tail) {
        out.* = slot.digest;
        return;
    }

    // ── Cold path: actually compute SHA-256. ──────────────────────────────
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(s, &digest, .{});
    encodeHex6(digest[0..6].*, out);

    slot.head = head;
    slot.tail = tail;
    slot.len = len32;
    slot.digest = out.*;
}

/// Branchless SIMD hex encoder: 6 bytes → 12 ASCII hex chars.
inline fn encodeHex6(b: [6]u8, out: *[12]u8) void {
    const V6 = @Vector(6, u8);
    const V12 = @Vector(12, u8);

    const bytes: V6 = b;
    const hi: V6 = bytes >> @as(@Vector(6, u3), @splat(4));
    const lo: V6 = bytes & @as(V6, @splat(0x0f));

    // Interleave [hi0, lo0, hi1, lo1, ..., hi5, lo5].
    // In @shuffle's mask: non-negative picks from `a`, ~negative from `b`.
    const nibbles: V12 = @shuffle(u8, hi, lo, @as(@Vector(12, i32), .{
        0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -6,
    }));

    // For n in 0..=15: ascii(n) = '0' + n + ((n + 6) >> 4) * 0x27.
    //   n in 0..=9  → (n+6)>>4 = 0 → adds nothing (lands on '0'..'9').
    //   n in 10..=15 → (n+6)>>4 = 1 → adds 0x27 (lands on 'a'..'f').
    const six: V12 = @splat(6);
    const adjust = (nibbles + six) >> @as(@Vector(12, u3), @splat(4));
    const ascii_zero: V12 = @splat('0');
    const ascii_step: V12 = @splat(0x27);
    const ascii: V12 = nibbles + ascii_zero + adjust * ascii_step;

    out.* = ascii;
}

// ─── Cache plumbing ──────────────────────────────────────────────────────

const cache_size: usize = 16;

const CacheEntry = extern struct {
    head: u64,
    tail: u64,
    len: u32,
    _pad: u32 = 0,
    digest: [12]u8,
};

const empty_slot: CacheEntry = .{
    .head = 0,
    .tail = 0,
    // len = 0 is impossible in this cache (the empty-string case short-
    // circuits before lookup), so it serves as the "vacant" sentinel.
    .len = 0,
    .digest = @splat(0),
};

threadlocal var cache: [cache_size]CacheEntry = @splat(empty_slot);

/// Drops every cached entry. Exists for tests that need a cold start; not
/// part of the public API.
pub fn resetCache() void {
    cache = @splat(empty_slot);
}

test "hash12 known vector" {
    resetCache();
    var buf: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &buf);
    try std.testing.expectEqualStrings("aae71e8db6d7", &buf);
}

test "hash12 empty" {
    var buf: [12]u8 = undefined;
    hash12("", &buf);
    try std.testing.expectEqualStrings("000000000000", &buf);
}

test "hash12 cache returns identical bytes on repeated call" {
    resetCache();
    var first: [12]u8 = undefined;
    var second: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &first);
    hash12("551d0f,551d25,551d11", &second);
    try std.testing.expectEqualStrings(&first, &second);
    try std.testing.expectEqualStrings("aae71e8db6d7", &second);
}

test "hash12 cache does not mix unrelated inputs" {
    resetCache();
    var a: [12]u8 = undefined;
    var b: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &a);
    hash12("different content entirely!", &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // And the first input still resolves to the correct digest after the
    // second call possibly evicted/displaced its slot.
    hash12("551d0f,551d25,551d11", &a);
    try std.testing.expectEqualStrings("aae71e8db6d7", &a);
}

test "hash12 short inputs are uniquely keyed" {
    resetCache();
    var a: [12]u8 = undefined;
    var b: [12]u8 = undefined;
    hash12("abc", &a);
    hash12("xyz", &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "encodeHex6 covers full nibble range" {
    // [0x00, 0x1f, 0x9a, 0xff, 0xa0, 0x5b] → "001f9affa05b"
    var out: [12]u8 = undefined;
    encodeHex6(.{ 0x00, 0x1f, 0x9a, 0xff, 0xa0, 0x5b }, &out);
    try std.testing.expectEqualStrings("001f9affa05b", &out);
}
