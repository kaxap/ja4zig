//! tshark subprocess driver + Packet/Proto abstractions.
//!
//! Spawns `tshark -r <pcap> -T ek -e frame.time_epoch` (NDJSON, one packet
//! per non-index line). Parses each packet's JSON into a `std.json.Value`
//! tree (arena-allocated, reset between packets), then exposes the
//! `Packet`/`Proto` view that the per-protocol modules expect.
//!
//! Field-name convention: the upstream Rust impl uses rtshark-style names
//! like `tls.handshake.extension.type` for layer `tls`. tshark's `-T ek`
//! encodes those as `tls_tls_handshake_extension_type` (layer-name prefix +
//! dot-to-underscore). `Proto.first()` / `Proto.values()` translate on the
//! fly so call sites stay readable.

const std = @import("std");

pub const PacketNum = u32;

/// Per-packet view backed by a parsed `std.json.Value`.
pub const Packet = struct {
    layers: *std.json.ObjectMap, // tshark's `layers` object
    num: PacketNum,
    timestamp_us: i64, // microseconds since unix epoch, from frame.time_epoch
    /// Per-packet arena (reset between packets). Field accessors format
    /// numeric JSON scalars into this so the returned slices stay valid for
    /// the same lifetime as the string-valued ones (until the next packet).
    arena: std.mem.Allocator,

    /// First layer with the given name. tshark's `-T ek` represents repeated
    /// layers (e.g. inner+outer IP in a GRE tunnel) as a JSON array; this
    /// returns the array's first element. See `lastProto` for the inner-most
    /// one (which is what stream identification wants).
    pub fn findProto(self: Packet, name: []const u8) ?Proto {
        if (self.layers.getPtr(name)) |entry| {
            const obj = switch (entry.*) {
                .object => |*o| o,
                .array => |*a| if (a.items.len == 0) return null else switch (a.items[0]) {
                    .object => |*o| o,
                    else => return null,
                },
                else => return null,
            };
            return .{ .name = name, .fields = obj, .packet_num = self.num, .arena = self.arena };
        }
        // Fall back to nested layers — TLS rides inside `quic` CRYPTO frames.
        // tshark exposes `quic.tls` as either an object (one frame) or an
        // array (multiple TLS frames in one QUIC packet); `quic` itself can
        // also be an array when one datagram carries multiple QUIC packets.
        // We pick the first nested tls that actually contains a handshake
        // — that's the one we want to fingerprint.
        if (std.mem.eql(u8, name, "tls")) {
            const q_entry = self.layers.getPtr("quic") orelse return null;
            switch (q_entry.*) {
                .object => |*q_obj| if (findNestedTls(q_obj)) |o| return .{ .name = name, .fields = o, .packet_num = self.num, .arena = self.arena },
                .array => |*arr| for (arr.items) |*el| switch (el.*) {
                    .object => |*q_obj| if (findNestedTls(q_obj)) |o| return .{ .name = name, .fields = o, .packet_num = self.num, .arena = self.arena },
                    else => {},
                },
                else => {},
            }
        }
        return null;
    }

    fn findNestedTls(quic_obj: *std.json.ObjectMap) ?*std.json.ObjectMap {
        const tls_val = quic_obj.getPtr("tls") orelse return null;
        switch (tls_val.*) {
            // A single CRYPTO frame: use it whether or not it carries a
            // handshake type, so we still surface SNI / cipher when present.
            .object => |*o| return o,
            .array => |*arr| {
                // Prefer an element that actually carries `tls.handshake.type`.
                for (arr.items) |*el| switch (el.*) {
                    .object => |*o| if (hasHandshake(o)) return o,
                    else => {},
                };
                // None has a handshake — use the first object so we at least
                // surface fields like SNI / cipher when present.
                for (arr.items) |*el| switch (el.*) {
                    .object => |*o| return o,
                    else => {},
                };
            },
            else => {},
        }
        return null;
    }

    fn hasHandshake(tls_obj: *const std.json.ObjectMap) bool {
        return tls_obj.contains("tls_tls_handshake_type");
    }

    pub fn lastProto(self: Packet, name: []const u8) ?Proto {
        const entry = self.layers.getPtr(name) orelse return null;
        const obj = switch (entry.*) {
            .object => |*o| o,
            .array => |*a| if (a.items.len == 0) return null else switch (a.items[a.items.len - 1]) {
                .object => |*o| o,
                else => return null,
            },
            else => return null,
        };
        return .{ .name = name, .fields = obj, .packet_num = self.num, .arena = self.arena };
    }

    pub fn hasProto(self: Packet, name: []const u8) bool {
        return self.layers.get(name) != null;
    }
};

/// One layer / protocol within a packet.
pub const Proto = struct {
    name: []const u8,
    fields: *const std.json.ObjectMap,
    packet_num: PacketNum,
    arena: std.mem.Allocator,

    /// Returns the first string-valued occurrence of `field_name`.
    /// `field_name` follows the rtshark convention (e.g. `tcp.flags`,
    /// `tls.handshake.extension.type`); we translate to the ek encoding
    /// (`tcp_tcp_flags`, `tls_tls_handshake_extension_type`).
    pub fn first(self: Proto, field_name: []const u8) ?[]const u8 {
        var key_buf: [256]u8 = undefined;
        const key = ekKey(&key_buf, self.name, field_name) orelse return null;
        const v = self.fields.getPtr(key) orelse return null;
        // For array-valued fields, "first" is the first element.
        return switch (v.*) {
            .array => |a| if (a.items.len == 0) null else scalarToStr(self.arena, a.items[0]),
            else => scalarToStr(self.arena, v.*),
        };
    }

    /// Iterates all values for `field_name`. tshark encodes repeated fields
    /// as a JSON array, single fields as a scalar — this normalises.
    pub fn values(self: Proto, field_name: []const u8) ValueIter {
        var key_buf: [256]u8 = undefined;
        const key = ekKey(&key_buf, self.name, field_name) orelse return .empty;
        const v = self.fields.getPtr(key) orelse return .empty;
        return switch (v.*) {
            .array => |*a| .{ .kind = .array, .arr = a, .idx = 0, .scalar = null, .arena = self.arena },
            else => .{ .kind = .scalar, .arr = null, .idx = 0, .scalar = scalarToStr(self.arena, v.*), .arena = self.arena },
        };
    }
};

pub const ValueIter = struct {
    kind: Kind,
    arr: ?*const std.json.Array,
    idx: usize,
    scalar: ?[]const u8,
    /// Used to format numeric array elements lazily in `next`. Unused (and
    /// `undefined`) for the `empty` iterator, which only ever yields null.
    arena: std.mem.Allocator,

    pub const Kind = enum { array, scalar };
    pub const empty: ValueIter = .{ .kind = .scalar, .arr = null, .idx = 0, .scalar = null, .arena = undefined };

    pub fn next(self: *ValueIter) ?[]const u8 {
        switch (self.kind) {
            .scalar => {
                if (self.scalar) |s| {
                    self.scalar = null;
                    return s;
                }
                return null;
            },
            .array => {
                const a = self.arr.?;
                while (self.idx < a.items.len) {
                    const v = a.items[self.idx];
                    self.idx += 1;
                    if (scalarToStr(self.arena, v)) |s| return s;
                }
                return null;
            },
        }
    }
};

/// Builds `<layer>_<field-name-with-dots-as-underscores>` into `buf`.
fn ekKey(buf: []u8, layer: []const u8, field: []const u8) ?[]const u8 {
    if (layer.len + 1 + field.len > buf.len) return null;
    var i: usize = 0;
    @memcpy(buf[i..][0..layer.len], layer);
    i += layer.len;
    buf[i] = '_';
    i += 1;
    for (field) |c| {
        buf[i] = if (c == '.') '_' else c;
        i += 1;
    }
    return buf[0..i];
}

/// Coerces a tshark scalar value (string/bool/integer) to a string slice.
/// Integers are formatted into `arena` (per-packet lifetime) so each call
/// returns an independent slice — no shared scratch buffer to alias.
/// Returns null for `float` / `null` / `object` / `array` values (arrays are
/// the caller's job — they iterate via `values` instead).
fn scalarToStr(arena: std.mem.Allocator, v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        .number_string => |s| s,
        .integer => |i| std.fmt.allocPrint(arena, "{d}", .{i}) catch null,
        .float => null,
        .bool => |b| if (b) "true" else "false",
        .null => null,
        .object, .array => null,
    };
}

// ─── Reader: streams packets out of a tshark subprocess ──────────────────

pub const Reader = struct {
    gpa: std.mem.Allocator,
    /// Captured stdout from tshark; lives until close().
    stdout: []u8,
    /// Iterator over newline-separated lines of `stdout`.
    lines: std.mem.SplitIterator(u8, .scalar),
    /// Arena reset between packets — holds the parsed JSON tree for the
    /// packet currently being yielded.
    packet_arena: std.heap.ArenaAllocator,
    /// Backing storage for `Packet.layers` (we project the object map out
    /// of the parsed value so the call sites don't have to switch on the
    /// outer Value tag every time).
    cur_value: ?std.json.Value,
    next_num: PacketNum,

    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        pcap_path: []const u8,
        keylog_path: ?[]const u8,
    ) !Reader {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{ "tshark", "-r", pcap_path, "-T", "ek" });
        if (keylog_path) |kp| {
            const opt = try std.fmt.allocPrint(gpa, "tls.keylog_file:{s}", .{kp});
            // NOTE: the option string outlives the spawn call (run captures
            // its own copies), so we free here.
            defer gpa.free(opt);
            try argv.appendSlice(gpa, &.{ "-o", opt });
        }

        const result = std.process.run(gpa, io, .{
            .argv = argv.items,
            .expand_arg0 = .expand,
        }) catch |err| {
            std.debug.print("ja4zig: failed to spawn tshark: {s}\n", .{@errorName(err)});
            return err;
        };
        // Discard stderr — tshark prints "interrupted" or "Running as user…"
        // on some setups; we don't care for the test path.
        gpa.free(result.stderr);
        switch (result.term) {
            .exited => |code| if (code != 0) {
                gpa.free(result.stdout);
                std.debug.print("ja4zig: tshark exited with code {d}\n", .{code});
                return error.TsharkFailed;
            },
            else => {
                gpa.free(result.stdout);
                return error.TsharkAborted;
            },
        }

        return .{
            .gpa = gpa,
            .stdout = result.stdout,
            .lines = std.mem.splitScalar(u8, result.stdout, '\n'),
            .packet_arena = .init(gpa),
            .cur_value = null,
            .next_num = 0,
        };
    }

    pub fn close(self: *Reader) void {
        self.packet_arena.deinit();
        self.gpa.free(self.stdout);
        self.* = undefined;
    }

    /// Yields the next packet (skipping `{"index":...}` lines). Memory for
    /// the returned packet is valid until the next call to `next()`.
    pub fn next(self: *Reader) !?Packet {
        // Reset the arena from the previous packet (if any).
        _ = self.packet_arena.reset(.retain_capacity);
        self.cur_value = null;

        while (self.lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &.{ ' ', '\t', '\r' });
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "{\"index\"")) continue;

            const aa = self.packet_arena.allocator();
            const parsed = std.json.parseFromSliceLeaky(std.json.Value, aa, trimmed, .{}) catch |err| {
                std.debug.print("ja4zig: skipping malformed packet JSON ({s})\n", .{@errorName(err)});
                continue;
            };
            switch (parsed) {
                .object => {},
                else => continue,
            }
            // Stash the parsed value in long-lived memory so we have stable
            // pointers into its tree until the next packet swaps it out.
            self.cur_value = parsed;
            const root_ptr = &self.cur_value.?;
            const root_obj = switch (root_ptr.*) {
                .object => |*o| o,
                else => continue,
            };
            const layers_value = root_obj.getPtr("layers") orelse continue;
            const layers = switch (layers_value.*) {
                .object => |*o| o,
                else => continue,
            };

            const ts = extractTimestampUs(layers);
            self.next_num += 1;
            return .{ .layers = layers, .num = self.next_num, .timestamp_us = ts, .arena = aa };
        }
        return null;
    }
};

fn extractTimestampUs(layers: *std.json.ObjectMap) i64 {
    // Read frame.time_epoch from the frame layer. tshark formats it as an
    // ISO timestamp like "2023-12-26T15:53:52.925092000Z" regardless of the
    // `-t` flag in -T ek mode. Convert that to unix microseconds.
    const frame_v = layers.get("frame") orelse return 0;
    const frame_obj = switch (frame_v) {
        .object => |*o| o,
        else => return 0,
    };
    const v = frame_obj.get("frame_frame_time_epoch") orelse return 0;
    const str = switch (v) {
        .string, .number_string => |s| s,
        .array => |a| if (a.items.len == 0) return 0 else switch (a.items[0]) {
            .string, .number_string => |s| s,
            else => return 0,
        },
        else => return 0,
    };
    return parseEpochToMicros(str);
}

/// Parses either a decimal-seconds form like `"1703606032.925092000"` or
/// the ISO form `"2023-12-26T15:53:52.925092000Z"` into unix microseconds.
pub fn parseEpochToMicros(s: []const u8) i64 {
    // Detect ISO vs decimal by looking for a 'T' in the first 11 chars.
    var iso = false;
    for (s[0..@min(s.len, 11)]) |c| {
        if (c == 'T') {
            iso = true;
            break;
        }
    }
    if (iso) return parseIsoToMicros(s);

    const dot = std.mem.indexOfScalar(u8, s, '.') orelse {
        const secs = std.fmt.parseInt(i64, s, 10) catch return 0;
        return secs * 1_000_000;
    };
    const secs = std.fmt.parseInt(i64, s[0..dot], 10) catch return 0;
    var frac: i64 = 0;
    var i: usize = dot + 1;
    var digits: usize = 0;
    while (i < s.len and digits < 6) : (i += 1) {
        const c = s[i];
        if (c < '0' or c > '9') break;
        frac = frac * 10 + @as(i64, c - '0');
        digits += 1;
    }
    while (digits < 6) : (digits += 1) frac *= 10;
    return secs * 1_000_000 + frac;
}

/// `"2023-12-26T15:53:52.925092000Z"` → 1_703_606_032_925_092.
fn parseIsoToMicros(s: []const u8) i64 {
    // Minimum: YYYY-MM-DDTHH:MM:SS = 19 chars.
    if (s.len < 19) return 0;
    const Y = std.fmt.parseInt(i64, s[0..4], 10) catch return 0;
    const Mo = std.fmt.parseInt(u32, s[5..7], 10) catch return 0;
    const D = std.fmt.parseInt(u32, s[8..10], 10) catch return 0;
    const H = std.fmt.parseInt(u32, s[11..13], 10) catch return 0;
    const Mi = std.fmt.parseInt(u32, s[14..16], 10) catch return 0;
    const Se = std.fmt.parseInt(u32, s[17..19], 10) catch return 0;
    var frac: i64 = 0;
    if (s.len > 20 and s[19] == '.') {
        var digits: usize = 0;
        var j: usize = 20;
        while (j < s.len and digits < 6) : (j += 1) {
            const c = s[j];
            if (c < '0' or c > '9') break;
            frac = frac * 10 + @as(i64, c - '0');
            digits += 1;
        }
        while (digits < 6) : (digits += 1) frac *= 10;
    }
    const days = daysSinceEpoch(Y, Mo, D);
    const secs = days * 86400 + @as(i64, H) * 3600 + @as(i64, Mi) * 60 + @as(i64, Se);
    return secs * 1_000_000 + frac;
}

fn daysSinceEpoch(year: i64, month: u32, day: u32) i64 {
    // Civil-from-days (Howard Hinnant's algorithm, inverted).
    var y = year;
    if (month <= 2) y -= 1;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: i64 = y - era * 400; // [0, 399]
    const m = month;
    const doy: i64 = @intCast(@divFloor(153 * @as(i64, @intCast(if (m > 2) m - 3 else m + 9)) + 2, 5) + day - 1);
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468; // 719468 = days from 0000-03-01 to 1970-01-01
}

test "ekKey conversion" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "tls_tls_handshake_extension_type",
        ekKey(&buf, "tls", "tls.handshake.extension.type").?,
    );
    try std.testing.expectEqualStrings(
        "tcp_tcp_flags",
        ekKey(&buf, "tcp", "tcp.flags").?,
    );
}

test "parseEpochToMicros decimal" {
    try std.testing.expectEqual(@as(i64, 1703606032925092), parseEpochToMicros("1703606032.925092000"));
    try std.testing.expectEqual(@as(i64, 1000000), parseEpochToMicros("1"));
    try std.testing.expectEqual(@as(i64, 1500000), parseEpochToMicros("1.5"));
}

test "parseEpochToMicros ISO" {
    try std.testing.expectEqual(@as(i64, 1703606032925092), parseEpochToMicros("2023-12-26T15:53:52.925092000Z"));
    try std.testing.expectEqual(@as(i64, 0), parseEpochToMicros("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(i64, 1_000_000), parseEpochToMicros("1970-01-01T00:00:01Z"));
}

test "integer-valued fields are independent slices (no shared-buffer aliasing)" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // tcp.window_size_value is a bare integer; tcp.option_kind is an integer
    // array. Both exercise the `.integer` path in scalarToStr.
    const json =
        \\{"layers":{"tcp":{"tcp_tcp_window_size_value":8192,"tcp_tcp_option_kind":[2,1,3]}}}
    ;
    var parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
    const root = switch (parsed) {
        .object => |*o| o,
        else => unreachable,
    };
    const layers = switch (root.getPtr("layers").?.*) {
        .object => |*o| o,
        else => unreachable,
    };
    const pkt: Packet = .{ .layers = layers, .num = 1, .timestamp_us = 0, .arena = arena };

    const tcp = pkt.findProto("tcp").?;

    // Hold a single-value integer slice live across an iteration that yields
    // several more integer slices. Under the old shared `num_buf` every one
    // of these would alias the same scratch bytes and clobber `ws`.
    const ws = tcp.first("tcp.window_size_value").?;
    try std.testing.expectEqualStrings("8192", ws);

    var it = tcp.values("tcp.option_kind");
    var kinds: [3][]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |v| : (n += 1) {
        try std.testing.expect(n < 3);
        kinds[n] = v;
    }
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("2", kinds[0]);
    try std.testing.expectEqualStrings("1", kinds[1]);
    try std.testing.expectEqualStrings("3", kinds[2]);
    // The originally-fetched value must survive the intervening conversions.
    try std.testing.expectEqualStrings("8192", ws);
}
