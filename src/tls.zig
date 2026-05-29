//! JA4 (TLS client) + JA4S (TLS server) per `rust/ja4/src/tls.rs`.

const std = @import("std");
const pcap = @import("pcap.zig");
const grease = @import("grease.zig");
const hash = @import("hash.zig");
const ja4x = @import("ja4x.zig");
const Sender = @import("stream.zig").Sender;

// Owned strings for the ServerName and ciphers/exts arrays. Caller arena
// (the per-stream allocator on Stream.alloc) frees them.
pub const ClientStats = struct {
    pkt_num: pcap.PacketNum,
    tls_ver_code: u16,
    /// Ciphers in original order, hex (no `0x`), GREASE-filtered.
    ciphers: [][]u8,
    /// Extension type values in original order, GREASE-filtered.
    exts: []u16,
    sni: ?[]u8, // owned
    /// First+last char of the first ALPN protocol; replaced with `'9'` if
    /// the byte isn't ASCII; `null` if no ALPN at all.
    alpn0: ?u8,
    alpn1: ?u8,
    sig_hash_algs: [][]u8, // hex w/o 0x
    has_ext_57: bool, // quic_transport_parameters
};

pub const ServerStats = struct {
    pkt_num: pcap.PacketNum,
    is_quic: bool,
    tls_ver_code: u16,
    cipher_hex: []u8, // owned, no `0x`
    exts: []u16,
    alpn0: ?u8,
    alpn1: ?u8,
};

pub const State = struct {
    client: ?ClientStats = null,
    server: ?ServerStats = null,
    x509: ja4x.State = .{},

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        if (self.client) |*c| {
            for (c.ciphers) |s| gpa.free(s);
            gpa.free(c.ciphers);
            gpa.free(c.exts);
            if (c.sni) |s| gpa.free(s);
            for (c.sig_hash_algs) |s| gpa.free(s);
            gpa.free(c.sig_hash_algs);
        }
        if (self.server) |*s| {
            gpa.free(s.cipher_hex);
            gpa.free(s.exts);
        }
        self.x509.deinit(gpa);
        self.* = .{};
    }
};

pub fn update(state: *State, pkt: pcap.Packet, gpa: std.mem.Allocator) !void {
    const tls = pkt.findProto("tls") orelse return;
    var has_cert_type = false;
    var type_it = tls.values("tls.handshake.type");
    while (type_it.next()) |t| {
        if (std.mem.eql(u8, t, "1")) {
            if (state.client == null) state.client = try buildClient(tls, pkt, gpa);
        } else if (std.mem.eql(u8, t, "2")) {
            if (state.server == null) state.server = try buildServer(tls, pkt, gpa);
        } else if (std.mem.eql(u8, t, "11")) {
            has_cert_type = true;
        }
    }
    if (has_cert_type) {
        var recs: std.ArrayList(ja4x.Record) = .empty;
        errdefer {
            for (recs.items) |*r| r.deinit(gpa);
            recs.deinit(gpa);
        }
        var c_it = tls.values("tls.handshake.certificate");
        while (c_it.next()) |hex| {
            if (try ja4x.buildRecord(gpa, pkt.num, hex)) |rec| try recs.append(gpa, rec);
        }
        if (recs.items.len > 0) {
            try state.x509.groups.append(gpa, .{
                .pkt_num = pkt.num,
                .records = try recs.toOwnedSlice(gpa),
            });
        }
    }
}

fn buildClient(tls: pcap.Proto, pkt: pcap.Packet, gpa: std.mem.Allocator) !ClientStats {
    // 1) extensions list (GREASE-filtered, original order)
    var exts: std.ArrayList(u16) = .empty;
    errdefer exts.deinit(gpa);
    var ext_it = tls.values("tls.handshake.extension.type");
    while (ext_it.next()) |e| {
        const v = std.fmt.parseInt(u32, e, 10) catch continue;
        if (grease.isGreaseInt(v)) continue;
        try exts.append(gpa, @intCast(v));
    }

    // 2) TLS version
    const tls_ver_code: u16 = blk: {
        if (containsExt(exts.items, 43)) {
            var best: ?u16 = null;
            var sv_it = tls.values("tls.handshake.extensions.supported_version");
            while (sv_it.next()) |s| {
                const v = parseVersionField(s) orelse continue;
                if (grease.isGreaseInt(v)) continue;
                if (best == null or v > best.?) best = v;
            }
            if (best) |b| break :blk b;
        }
        if (tls.first("tls.handshake.version")) |s| break :blk parseVersionField(s) orelse 0;
        break :blk 0;
    };

    // 3) SNI
    var sni: ?[]u8 = null;
    if (tls.first("tls.handshake.extensions_server_name")) |s| {
        sni = try gpa.dupe(u8, s);
    }

    // 4) ALPN: first ALPN protocol's first+last byte (with '9' for non-ASCII)
    var alpn0: ?u8 = null;
    var alpn1: ?u8 = null;
    if (tls.first("tls.handshake.extensions_alpn_str")) |alpn_str| {
        if (alpn_str.len > 0) {
            alpn0 = asciiOr9(alpn_str[0]);
            if (alpn_str.len > 1) alpn1 = asciiOr9(alpn_str[alpn_str.len - 1]);
        }
    }

    // 5) Ciphers (GREASE-filtered, normalised to 4-char lowercase hex)
    var ciphers: std.ArrayList([]u8) = .empty;
    errdefer {
        for (ciphers.items) |c| gpa.free(c);
        ciphers.deinit(gpa);
    }
    var c_it = tls.values("tls.handshake.ciphersuite");
    while (c_it.next()) |s| {
        const v = parseVersionField(s) orelse continue; // u16 parser is reusable
        if (grease.isGreaseInt(v)) continue;
        const buf = try gpa.alloc(u8, 4);
        _ = std.fmt.bufPrint(buf, "{x:0>4}", .{v}) catch unreachable;
        try ciphers.append(gpa, buf);
    }

    // 6) Sig-hash algs: only those under extension 13 (signature_algorithms).
    //    tshark's `-T ek` collapses duplicates, but the Rust code walks
    //    rtshark's flat field stream and only takes sig_hash_alg values
    //    that immediately follow the ext-type=13 marker. With ek we don't
    //    have ordering info between extension blocks; the practical effect
    //    is that `tls.handshake.sig_hash_alg` here may include values from
    //    other extensions (e.g. delegated_credentials). For JA4 correctness
    //    this matters in rare browsers — we accept the imprecision and
    //    revisit if a snapshot diverges.
    var sigs: std.ArrayList([]u8) = .empty;
    errdefer {
        for (sigs.items) |s| gpa.free(s);
        sigs.deinit(gpa);
    }
    if (containsExt(exts.items, 13)) {
        // tshark's `-T ek` collapses sig_hash_alg into one array across every
        // sig-carrying extension (13 = signature_algorithms, 34 =
        // delegated_credentials, 50 = signature_algorithms_cert). To extract
        // *just* ext 13's portion we determine its position among the
        // sig-carrying extensions and slice into `sig_hash_alg_len`.
        const sig_exts = [_]u16{ 13, 34, 50 };
        var ext13_pos: usize = 0;
        var counted: usize = 0;
        var found = false;
        for (exts.items) |e| {
            if (e == 13) {
                ext13_pos = counted;
                found = true;
                break;
            }
            for (sig_exts) |se| if (e == se) {
                counted += 1;
                break;
            };
        }
        if (found) {
            var lens: std.ArrayList(u32) = .empty;
            defer lens.deinit(gpa);
            var len_it = tls.values("tls.handshake.sig_hash_alg_len");
            while (len_it.next()) |s| {
                const v = std.fmt.parseInt(u32, s, 10) catch continue;
                try lens.append(gpa, v);
            }
            var skip: u32 = 0;
            for (lens.items[0..@min(ext13_pos, lens.items.len)]) |L| skip += L / 2;
            const take: u32 = if (ext13_pos < lens.items.len) lens.items[ext13_pos] / 2 else 0;
            var i: u32 = 0;
            var sig_it = tls.values("tls.handshake.sig_hash_alg");
            while (sig_it.next()) |s| : (i += 1) {
                if (i < skip) continue;
                if (i >= skip + take) break;
                const v = parseVersionField(s) orelse continue;
                const buf = try gpa.alloc(u8, 4);
                _ = std.fmt.bufPrint(buf, "{x:0>4}", .{v}) catch unreachable;
                try sigs.append(gpa, buf);
            }
        }
    }

    const has_57 = containsExt(exts.items, 57);
    return .{
        .pkt_num = pkt.num,
        .tls_ver_code = tls_ver_code,
        .ciphers = try ciphers.toOwnedSlice(gpa),
        .exts = try exts.toOwnedSlice(gpa),
        .sni = sni,
        .alpn0 = alpn0,
        .alpn1 = alpn1,
        .sig_hash_algs = try sigs.toOwnedSlice(gpa),
        .has_ext_57 = has_57,
    };
}

fn buildServer(tls: pcap.Proto, pkt: pcap.Packet, gpa: std.mem.Allocator) !ServerStats {
    var exts: std.ArrayList(u16) = .empty;
    errdefer exts.deinit(gpa);
    var ext_it = tls.values("tls.handshake.extension.type");
    while (ext_it.next()) |e| {
        const v = std.fmt.parseInt(u32, e, 10) catch continue;
        try exts.append(gpa, @intCast(v));
    }

    const tls_ver_code: u16 = blk: {
        if (containsExt(exts.items, 43)) {
            var best: ?u16 = null;
            var sv_it = tls.values("tls.handshake.extensions.supported_version");
            while (sv_it.next()) |s| {
                const v = parseVersionField(s) orelse continue;
                if (grease.isGreaseInt(v)) continue;
                if (best == null or v > best.?) best = v;
            }
            if (best) |b| break :blk b;
        }
        if (tls.first("tls.handshake.version")) |s| break :blk parseVersionField(s) orelse 0;
        break :blk 0;
    };

    // Cipher (single value) — tshark gives decimal, we want 4-char hex.
    const cipher_hex = blk: {
        const s = tls.first("tls.handshake.ciphersuite") orelse return error.NoCipher;
        const v = parseVersionField(s) orelse return error.UnexpectedCipher;
        const buf = try gpa.alloc(u8, 4);
        _ = std.fmt.bufPrint(buf, "{x:0>4}", .{v}) catch unreachable;
        break :blk buf;
    };
    errdefer gpa.free(cipher_hex);

    var alpn0: ?u8 = null;
    var alpn1: ?u8 = null;
    if (tls.first("tls.handshake.extensions_alpn_str")) |alpn_str| {
        if (alpn_str.len > 0) {
            alpn0 = asciiOr9(alpn_str[0]);
            if (alpn_str.len > 1) alpn1 = asciiOr9(alpn_str[alpn_str.len - 1]);
        }
    }

    return .{
        .pkt_num = pkt.num,
        .is_quic = pkt.hasProto("udp"),
        .tls_ver_code = tls_ver_code,
        .cipher_hex = cipher_hex,
        .exts = try exts.toOwnedSlice(gpa),
        .alpn0 = alpn0,
        .alpn1 = alpn1,
    };
}

fn containsExt(exts: []const u16, want: u16) bool {
    for (exts) |e| if (e == want) return true;
    return false;
}

/// tshark `-T ek` may emit a version as decimal (`"771"`) or hex (`"0x0303"`)
/// depending on the field. Accept either.
fn parseVersionField(s: []const u8) ?u16 {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        const v = std.fmt.parseInt(u32, s[2..], 16) catch return null;
        return @intCast(v & 0xffff);
    }
    const v = std.fmt.parseInt(u32, s, 10) catch return null;
    return @intCast(v & 0xffff);
}

fn asciiOr9(c: u8) u8 {
    // Treats any non-printable-ASCII byte (>=0x80) as '9'. The Rust impl
    // does the same; pcap fixtures include one TLS hello whose ALPN is
    // non-ASCII (tls-non-ascii-alpn.pcapng) and the expected snapshot
    // shows the `9` substitution.
    if (c >= 0x20 and c <= 0x7e) return c;
    return '9';
}

fn tlsVerLetter(code: u16) []const u8 {
    return switch (code) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        else => "00",
    };
}

pub fn emitServerName(state: State, w: *std.Io.Writer) !void {
    const c = state.client orelse return;
    const sni = c.sni orelse return;
    try w.print("  tls_server_name: ", .{});
    try @import("yaml.zig").writeScalar(w, sni);
    try w.print("\n", .{});
}

pub fn emitClient(
    state: State,
    w: *std.Io.Writer,
    gpa: std.mem.Allocator,
    with_packet_numbers: bool,
    with_raw: bool,
    original_order: bool,
) !void {
    const c = state.client orelse return;
    if (with_packet_numbers) try w.print("  pkt_ja4: {d}\n", .{c.pkt_num});

    const quic_letter: u8 = if (c.has_ext_57) 'q' else 't';
    const sni_marker: u8 = if (containsExt(c.exts, 0)) 'd' else 'i';
    const nr_ciphers = @min(c.ciphers.len, 99);
    const nr_exts = @min(c.exts.len, 99);
    const a0: u8 = c.alpn0 orelse '0';
    const a1: u8 = c.alpn1 orelse '0';
    const ver = tlsVerLetter(c.tls_ver_code);

    var first_chunk_buf: [16]u8 = undefined;
    const first_chunk = try std.fmt.bufPrint(&first_chunk_buf, "{c}{s}{c}{d:0>2}{d:0>2}{c}{c}", .{
        quic_letter, ver, sni_marker, nr_ciphers, nr_exts, a0, a1,
    });

    // Sort ciphers + exts unless original_order. Also drop ext 0 and 16
    // (SNI, ALPN) before serialising — but only when sorting is on.
    const ciphers_buf = try gpa.alloc([]u8, c.ciphers.len);
    defer gpa.free(ciphers_buf);
    @memcpy(ciphers_buf, c.ciphers);

    const exts_buf = try gpa.alloc(u16, c.exts.len);
    defer gpa.free(exts_buf);
    @memcpy(exts_buf, c.exts);

    var exts_for_emit_len: usize = exts_buf.len;
    if (!original_order) {
        std.mem.sort([]u8, ciphers_buf, {}, lessThanHexStr);
        std.mem.sort(u16, exts_buf, {}, std.sort.asc(u16));
        // Drop 0x0000 and 0x0010
        var write_i: usize = 0;
        for (exts_buf) |e| {
            if (e == 0 or e == 16) continue;
            exts_buf[write_i] = e;
            write_i += 1;
        }
        exts_for_emit_len = write_i;
    }

    // Build ciphers_str and exts_sigs strings.
    var ciphers_str: std.ArrayList(u8) = .empty;
    defer ciphers_str.deinit(gpa);
    for (ciphers_buf, 0..) |s, i| {
        if (i != 0) try ciphers_str.append(gpa, ',');
        try ciphers_str.appendSlice(gpa, s);
    }

    var exts_sigs: std.ArrayList(u8) = .empty;
    defer exts_sigs.deinit(gpa);
    for (exts_buf[0..exts_for_emit_len], 0..) |e, i| {
        if (i != 0) try exts_sigs.append(gpa, ',');
        var hex_buf: [4]u8 = undefined;
        const hex_s = try std.fmt.bufPrint(&hex_buf, "{x:0>4}", .{e});
        try exts_sigs.appendSlice(gpa, hex_s);
    }
    if (c.sig_hash_algs.len > 0) {
        try exts_sigs.append(gpa, '_');
        for (c.sig_hash_algs, 0..) |s, i| {
            if (i != 0) try exts_sigs.append(gpa, ',');
            try exts_sigs.appendSlice(gpa, s);
        }
    }

    var h_ciphers: [12]u8 = undefined;
    hash.hash12(ciphers_str.items, &h_ciphers);
    var h_exts: [12]u8 = undefined;
    hash.hash12(exts_sigs.items, &h_exts);

    const ja4_key: []const u8 = if (original_order) "ja4_o" else "ja4";
    try w.print("  {s}: {s}_{s}_{s}\n", .{ ja4_key, first_chunk, &h_ciphers, &h_exts });
    if (with_raw) {
        const raw_key: []const u8 = if (original_order) "ja4_ro" else "ja4_r";
        try w.print("  {s}: {s}_{s}_{s}\n", .{ raw_key, first_chunk, ciphers_str.items, exts_sigs.items });
    }
}

pub fn emitX509(state: State, w: *std.Io.Writer, with_packet_numbers: bool, with_raw: bool) !void {
    try ja4x.emit(state.x509, w, with_packet_numbers, with_raw);
}

pub fn emitServer(
    state: State,
    w: *std.Io.Writer,
    gpa: std.mem.Allocator,
    with_packet_numbers: bool,
    with_raw: bool,
) !void {
    const s = state.server orelse return;
    if (with_packet_numbers) try w.print("  pkt_ja4s: {d}\n", .{s.pkt_num});

    const quic_letter: u8 = if (s.is_quic) 'q' else 't';
    const nr_exts = @min(s.exts.len, 99);
    const a0: u8 = s.alpn0 orelse '0';
    const a1: u8 = s.alpn1 orelse '0';
    const ver = tlsVerLetter(s.tls_ver_code);

    var two_chunks_buf: [32]u8 = undefined;
    const two_chunks = try std.fmt.bufPrint(&two_chunks_buf, "{c}{s}{d:0>2}{c}{c}_{s}", .{
        quic_letter, ver, nr_exts, a0, a1, s.cipher_hex,
    });

    var exts_str: std.ArrayList(u8) = .empty;
    defer exts_str.deinit(gpa);
    for (s.exts, 0..) |e, i| {
        if (i != 0) try exts_str.append(gpa, ',');
        var hex_buf: [4]u8 = undefined;
        const hex_s = try std.fmt.bufPrint(&hex_buf, "{x:0>4}", .{e});
        try exts_str.appendSlice(gpa, hex_s);
    }

    var h: [12]u8 = undefined;
    hash.hash12(exts_str.items, &h);

    try w.print("  ja4s: {s}_{s}\n", .{ two_chunks, &h });
    if (with_raw) try w.print("  ja4s_r: {s}_{s}\n", .{ two_chunks, exts_str.items });
}

fn lessThanHexStr(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}
