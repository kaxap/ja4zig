//! JA4H — HTTP client fingerprint. Mirrors `rust/ja4/src/http.rs`.

const std = @import("std");
const pcap = @import("pcap.zig");
const hash = @import("hash.zig");

pub const HttpStats = struct {
    pkt_num: pcap.PacketNum,
    method_code: [2]u8, // "ge", "po", ...
    version_code: [2]u8, // "10", "11", "20", "30"
    has_cookie: bool,
    has_referer: bool,
    language: ?[]u8, // owned
    headers: [][]u8, // owned (header names in occurrence order, EXCLUDING cookie/referer)
    cookie_pairs: []CookiePair,

    pub fn deinit(self: *HttpStats, gpa: std.mem.Allocator) void {
        if (self.language) |l| gpa.free(l);
        for (self.headers) |h| gpa.free(h);
        gpa.free(self.headers);
        for (self.cookie_pairs) |p| {
            gpa.free(p.name);
            if (p.value) |v| gpa.free(v);
        }
        gpa.free(self.cookie_pairs);
    }
};

pub const CookiePair = struct {
    name: []u8,
    value: ?[]u8,
};

pub const State = struct {
    requests: std.ArrayList(HttpStats) = .empty,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        for (self.requests.items) |*r| r.deinit(gpa);
        self.requests.deinit(gpa);
    }
};

pub fn update(state: *State, pkt: pcap.Packet, gpa: std.mem.Allocator) !void {
    if (pkt.findProto("http")) |http| {
        if (try buildHttp1(http, pkt, gpa)) |stats| try state.requests.append(gpa, stats);
        return;
    }
    if (pkt.findProto("http2")) |http2| {
        if (try buildHttp2(http2, pkt, gpa)) |stats| try state.requests.append(gpa, stats);
    }
}

fn buildHttp1(http: pcap.Proto, pkt: pcap.Packet, gpa: std.mem.Allocator) !?HttpStats {
    const method = http.first("http.request.method") orelse return null;
    const method_code = methodCode(method) orelse return null;
    const version_str = http.first("http.request.version") orelse return null;
    const version_code = http1VersionCode(version_str) orelse return null;

    var language: ?[]u8 = null;
    if (http.first("http.accept_language")) |l| language = try gpa.dupe(u8, l);
    errdefer if (language) |l| gpa.free(l);

    var headers: std.ArrayList([]u8) = .empty;
    errdefer {
        for (headers.items) |h| gpa.free(h);
        headers.deinit(gpa);
    }
    var has_cookie = false;
    var has_referer = false;
    var line_it = http.values("http.request.line");
    while (line_it.next()) |line| {
        // Header name is everything before the first ':' .
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        if (asciiCaseEql(name, "cookie")) {
            has_cookie = true;
            continue;
        }
        if (asciiCaseEql(name, "referer")) {
            has_referer = true;
            continue;
        }
        try headers.append(gpa, try gpa.dupe(u8, name));
    }

    var cookie_pairs: std.ArrayList(CookiePair) = .empty;
    errdefer {
        for (cookie_pairs.items) |p| {
            gpa.free(p.name);
            if (p.value) |v| gpa.free(v);
        }
        cookie_pairs.deinit(gpa);
    }
    if (http.first("http.cookie")) |cookies| {
        try parseCookies(cookies, &cookie_pairs, gpa);
    }

    return .{
        .pkt_num = pkt.num,
        .method_code = method_code,
        .version_code = version_code,
        .has_cookie = has_cookie,
        .has_referer = has_referer,
        .language = language,
        .headers = try headers.toOwnedSlice(gpa),
        .cookie_pairs = try cookie_pairs.toOwnedSlice(gpa),
    };
}

fn buildHttp2(http2: pcap.Proto, pkt: pcap.Packet, gpa: std.mem.Allocator) !?HttpStats {
    const method = http2.first("http2.headers.method") orelse return null;
    const method_code = methodCode(method) orelse return null;

    var language: ?[]u8 = null;
    if (http2.first("http2.headers.accept_language")) |l| language = try gpa.dupe(u8, l);
    errdefer if (language) |l| gpa.free(l);

    var headers: std.ArrayList([]u8) = .empty;
    errdefer {
        for (headers.items) |h| gpa.free(h);
        headers.deinit(gpa);
    }
    var has_cookie = false;
    var has_referer = false;
    var hn_it = http2.values("http2.header.name");
    while (hn_it.next()) |name| {
        if (std.mem.eql(u8, name, "cookie")) {
            has_cookie = true;
            continue;
        }
        if (std.mem.eql(u8, name, "referer")) {
            has_referer = true;
            continue;
        }
        try headers.append(gpa, try gpa.dupe(u8, name));
    }

    var cookie_pairs: std.ArrayList(CookiePair) = .empty;
    errdefer {
        for (cookie_pairs.items) |p| {
            gpa.free(p.name);
            if (p.value) |v| gpa.free(v);
        }
        cookie_pairs.deinit(gpa);
    }
    var ck_it = http2.values("http2.headers.cookie");
    while (ck_it.next()) |raw| {
        try parseOneCookie(raw, &cookie_pairs, gpa);
    }

    return .{
        .pkt_num = pkt.num,
        .method_code = method_code,
        .version_code = .{ '2', '0' },
        .has_cookie = has_cookie,
        .has_referer = has_referer,
        .language = language,
        .headers = try headers.toOwnedSlice(gpa),
        .cookie_pairs = try cookie_pairs.toOwnedSlice(gpa),
    };
}

fn parseCookies(s: []const u8, out: *std.ArrayList(CookiePair), gpa: std.mem.Allocator) !void {
    // Split on "; " per the Rust impl.
    var i: usize = 0;
    while (i < s.len) {
        var end = i;
        while (end + 1 < s.len and !(s[end] == ';' and s[end + 1] == ' ')) : (end += 1) {}
        const slice_end = if (end + 1 < s.len) end else s.len;
        try parseOneCookie(s[i..slice_end], out, gpa);
        if (end + 1 < s.len) i = end + 2 else break;
    }
}

fn parseOneCookie(raw: []const u8, out: *std.ArrayList(CookiePair), gpa: std.mem.Allocator) !void {
    if (raw.len == 0) return;
    if (std.mem.indexOfScalar(u8, raw, '=')) |eq| {
        try out.append(gpa, .{
            .name = try gpa.dupe(u8, raw[0..eq]),
            .value = try gpa.dupe(u8, raw[eq + 1 ..]),
        });
    } else {
        try out.append(gpa, .{ .name = try gpa.dupe(u8, raw), .value = null });
    }
}

fn methodCode(m: []const u8) ?[2]u8 {
    if (std.mem.eql(u8, m, "CONNECT")) return .{ 'c', 'o' };
    if (std.mem.eql(u8, m, "DELETE")) return .{ 'd', 'e' };
    if (std.mem.eql(u8, m, "GET")) return .{ 'g', 'e' };
    if (std.mem.eql(u8, m, "HEAD")) return .{ 'h', 'e' };
    if (std.mem.eql(u8, m, "OPTIONS")) return .{ 'o', 'p' };
    if (std.mem.eql(u8, m, "PATCH")) return .{ 'p', 'a' };
    if (std.mem.eql(u8, m, "POST")) return .{ 'p', 'o' };
    if (std.mem.eql(u8, m, "PUT")) return .{ 'p', 'u' };
    if (std.mem.eql(u8, m, "TRACE")) return .{ 't', 'r' };
    return null;
}

fn http1VersionCode(v: []const u8) ?[2]u8 {
    if (std.mem.eql(u8, v, "HTTP/1.0")) return .{ '1', '0' };
    if (std.mem.eql(u8, v, "HTTP/1.1")) return .{ '1', '1' };
    if (std.mem.eql(u8, v, "HTTP/2")) return .{ '2', '0' };
    if (std.mem.eql(u8, v, "HTTP/3")) return .{ '3', '0' };
    return null;
}

fn asciiCaseEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

fn primaryLanguage(input: []const u8, out: *[4]u8) usize {
    // trim leading whitespace, take token before first ',', remove '-',
    // ASCII-lowercase, pad with '0' to length 4, truncate to 4 bytes.
    var i: usize = 0;
    while (i < input.len and (input[i] == ' ' or input[i] == '\t')) : (i += 1) {}
    var written: usize = 0;
    while (i < input.len and input[i] != ',' and written < 4) : (i += 1) {
        const c = input[i];
        if (c == '-') continue;
        out[written] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        written += 1;
    }
    while (written < 4) : (written += 1) out[written] = '0';
    return 4;
}

pub fn emit(
    state: State,
    w: *std.Io.Writer,
    gpa: std.mem.Allocator,
    with_packet_numbers: bool,
    with_raw: bool,
    original_order: bool,
) !void {
    if (state.requests.items.len == 0) return;
    try w.print("  http:\n", .{});
    for (state.requests.items) |*r| try emitOne(r, w, gpa, with_packet_numbers, with_raw, original_order);
}

fn emitOne(
    r: *HttpStats,
    w: *std.Io.Writer,
    gpa: std.mem.Allocator,
    with_packet_numbers: bool,
    with_raw: bool,
    original_order: bool,
) !void {
    const ck_marker: u8 = if (r.has_cookie) 'c' else 'n';
    const rf_marker: u8 = if (r.has_referer) 'r' else 'n';
    const nr_headers = @min(r.headers.len, 99);

    var lang_buf: [4]u8 = .{ '0', '0', '0', '0' };
    if (r.language) |l| _ = primaryLanguage(l, &lang_buf);

    // method(2) + version(2) + cookie_marker(1) + referer_marker(1)
    //   + nr_headers(2) + lang(4) = 12 chars.
    var first_chunk_buf: [16]u8 = undefined;
    const fc = try std.fmt.bufPrint(&first_chunk_buf, "{c}{c}{c}{c}{c}{c}{d:0>2}{c}{c}{c}{c}", .{
        r.method_code[0], r.method_code[1], r.version_code[0], r.version_code[1],
        ck_marker,        rf_marker,        nr_headers,
        lang_buf[0],      lang_buf[1],      lang_buf[2],       lang_buf[3],
    });

    var headers_str: std.ArrayList(u8) = .empty;
    defer headers_str.deinit(gpa);
    for (r.headers, 0..) |h, i| {
        if (i != 0) try headers_str.append(gpa, ',');
        try headers_str.appendSlice(gpa, h);
    }

    // Sort cookies if needed
    const sorted_cookies = try gpa.alloc(CookiePair, r.cookie_pairs.len);
    defer gpa.free(sorted_cookies);
    @memcpy(sorted_cookies, r.cookie_pairs);
    if (!original_order) std.mem.sort(CookiePair, sorted_cookies, {}, lessCookie);

    var cookie_names: std.ArrayList(u8) = .empty;
    defer cookie_names.deinit(gpa);
    var cookies_full: std.ArrayList(u8) = .empty;
    defer cookies_full.deinit(gpa);
    for (sorted_cookies, 0..) |p, i| {
        if (i != 0) {
            try cookie_names.append(gpa, ',');
            try cookies_full.append(gpa, ',');
        }
        try cookie_names.appendSlice(gpa, p.name);
        try cookies_full.appendSlice(gpa, p.name);
        if (p.value) |v| {
            try cookies_full.append(gpa, '=');
            try cookies_full.appendSlice(gpa, v);
        }
    }

    var h_headers: [12]u8 = undefined;
    hash.hash12(headers_str.items, &h_headers);
    var h_cknames: [12]u8 = undefined;
    hash.hash12(cookie_names.items, &h_cknames);
    var h_cookies: [12]u8 = undefined;
    hash.hash12(cookies_full.items, &h_cookies);

    if (with_packet_numbers) try w.print("  - pkt_ja4h: {d}\n    ", .{r.pkt_num}) else try w.print("  - ", .{});

    const key = if (original_order) "ja4h_o" else "ja4h";
    try w.print("{s}: {s}_{s}_{s}_{s}\n", .{ key, fc, &h_headers, &h_cknames, &h_cookies });
    if (with_raw) {
        const raw_key = if (original_order) "ja4h_ro" else "ja4h_r";
        try w.print("    {s}: {s}_{s}_{s}_{s}\n", .{ raw_key, fc, headers_str.items, cookie_names.items, cookies_full.items });
    }
}

fn lessCookie(_: void, a: CookiePair, b: CookiePair) bool {
    const name_order = std.mem.order(u8, a.name, b.name);
    if (name_order != .eq) return name_order == .lt;
    if (a.value == null and b.value != null) return true;
    if (a.value != null and b.value == null) return false;
    if (a.value == null and b.value == null) return false;
    return std.mem.order(u8, a.value.?, b.value.?) == .lt;
}
