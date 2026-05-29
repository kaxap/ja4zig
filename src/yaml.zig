//! Tiny YAML emitter for the subset insta produces in the upstream Rust
//! snapshots: top-level sequence of mappings, scalar strings/ints, nested
//! sequences and mappings. We never need flow style, no anchors, no tags.

const std = @import("std");

/// Emits a YAML scalar, quoting when needed. The set of "needs quoting" is
/// kept small and conservative to match insta/serde-yaml's output: leading
/// `*`, leading `-`, leading digit-with-special, or characters that would
/// be misparsed (`:` followed by space, `#`). For our domain the only
/// real-world cases are wildcard cert CNs (`*.adnxs.com`).
pub fn writeScalar(w: *std.Io.Writer, s: []const u8) !void {
    if (needsQuoting(s)) {
        try w.print("'", .{});
        // single-quote escape: doubled
        for (s) |c| {
            if (c == '\'') try w.print("''", .{}) else try w.print("{c}", .{c});
        }
        try w.print("'", .{});
    } else {
        try w.print("{s}", .{s});
    }
}

fn needsQuoting(s: []const u8) bool {
    if (s.len == 0) return true;
    switch (s[0]) {
        '*', '&', '!', '|', '>', '\'', '"', '%', '@', '`', '?', ',', '[', ']', '{', '}' => return true,
        '-' => {
            if (s.len == 1 or s[1] == ' ') return true;
        },
        ' ', '\t' => return true,
        else => {},
    }
    if (std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "false") or
        std.mem.eql(u8, s, "null") or std.mem.eql(u8, s, "yes") or
        std.mem.eql(u8, s, "no") or std.mem.eql(u8, s, "~")) return true;
    // Integer/float-like → quote so YAML doesn't widen the type.
    if (looksLikeNumber(s)) return true;
    for (s, 0..) |c, i| {
        if (c == '#' and (i == 0 or s[i - 1] == ' ' or s[i - 1] == '\t')) return true;
        if (c == ':' and (i + 1 == s.len or s[i + 1] == ' ')) return true;
    }
    return false;
}

fn looksLikeNumber(s: []const u8) bool {
    var i: usize = 0;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) i += 1;
    if (i == s.len) return false;
    var seen_digit = false;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) seen_digit = true;
    if (!seen_digit) return false;
    if (i == s.len) return true; // integer
    if (s[i] == '.') {
        i += 1;
        while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {}
        if (i == s.len) return true; // float
    }
    return false;
}

test "needsQuoting basics" {
    try std.testing.expect(!needsQuoting("foo"));
    try std.testing.expect(!needsQuoting("192.168.1.1"));
    try std.testing.expect(!needsQuoting("ja4ssh"));
    try std.testing.expect(needsQuoting("*.adnxs.com"));
    try std.testing.expect(needsQuoting(""));
    try std.testing.expect(needsQuoting("true"));
}
