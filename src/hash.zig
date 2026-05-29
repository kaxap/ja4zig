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
///     on Apple Silicon, SHA-NI on recent x86_64), so it's computed every
///     call. A prior version memoized digests under a (len, head8, tail8)
///     key, but that collided on JA4 extension lists sharing length, prefix,
///     and suffix while differing in the middle (seen on tls3.pcapng), so
///     the cache was removed.
///   • The hex tail is a 12-lane SIMD branchless conversion (`@shuffle` to
///     interleave hi/lo nibbles, then `n + '0' + ((n+6)>>4)*0x27`).
pub fn hash12(s: []const u8, out: *[12]u8) void {
    if (s.len == 0) {
        out.* = "000000000000".*;
        return;
    }

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(s, &digest, .{});
    encodeHex6(digest[0..6].*, out);
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

test "hash12 known vector" {
    var buf: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &buf);
    try std.testing.expectEqualStrings("aae71e8db6d7", &buf);
}

test "hash12 empty" {
    var buf: [12]u8 = undefined;
    hash12("", &buf);
    try std.testing.expectEqualStrings("000000000000", &buf);
}

test "hash12 is deterministic across repeated calls" {
    var first: [12]u8 = undefined;
    var second: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &first);
    hash12("551d0f,551d25,551d11", &second);
    try std.testing.expectEqualStrings(&first, &second);
    try std.testing.expectEqualStrings("aae71e8db6d7", &second);
}

test "hash12 distinguishes unrelated inputs" {
    var a: [12]u8 = undefined;
    var b: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &a);
    hash12("different content entirely!", &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // The first input still resolves to the correct digest afterwards.
    hash12("551d0f,551d25,551d11", &a);
    try std.testing.expectEqualStrings("aae71e8db6d7", &a);
}

test "hash12 short inputs differ" {
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
