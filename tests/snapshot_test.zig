//! Snapshot test harness.
//!
//! For every `*.pcap` / `*.pcapng` file under `tests/testdata/pcap/`, invokes
//! the locally-built `ja4` binary with no flags and diffs stdout against
//! `tests/testdata/snapshots/<basename>.yaml`.
//!
//! Performance: 37 subprocess spawns serially take ~2 s wall-clock even on
//! a fast box (≈50 ms tshark startup × 37). We fan the work out to a pool
//! of worker threads sized to the CPU count, each pulling pcap indices off
//! a shared atomic counter — roughly an Nx speedup. Within a worker, the
//! tasks are sequential (no shared mutable state besides the atomic index
//! and a per-pcap result slot, both lock-free).

const std = @import("std");
const build_options = @import("build_options");

const Io = std.Io;

const Slot = struct {
    name: []u8,
    /// null = success (bytes matched, exit 0). non-null = failure diff text;
    /// the worker owns the buffer until the main thread reads it.
    failure: ?[]u8,
};

const Shared = struct {
    gpa: std.mem.Allocator,
    io: Io,
    pcap_dir: []const u8,
    snapshots_dir_path: []const u8,
    names: []const []const u8,
    slots: []Slot,
    next: std.atomic.Value(usize),
};

test "snapshots match expected fingerprints" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var pcap_dir = try Io.Dir.cwd().openDir(io, build_options.pcap_dir, .{ .iterate = true });
    defer pcap_dir.close(io);

    // Collect pcap names up front so workers can index into them.
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    var it = pcap_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isPcapName(entry.name)) continue;
        try names.append(gpa, try gpa.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, ltStr);

    const slots = try gpa.alloc(Slot, names.items.len);
    defer gpa.free(slots);
    for (slots, names.items) |*slot, name| {
        slot.* = .{ .name = try gpa.dupe(u8, name), .failure = null };
    }
    defer for (slots) |slot| {
        gpa.free(slot.name);
        if (slot.failure) |buf| gpa.free(buf);
    };

    var shared: Shared = .{
        .gpa = gpa,
        .io = io,
        .pcap_dir = build_options.pcap_dir,
        .snapshots_dir_path = build_options.snapshots_dir,
        .names = names.items,
        .slots = slots,
        .next = .{ .raw = 0 },
    };

    // Cap parallelism at 8: each worker holds a child process + two pipe
    // buffers, and ≥8 in-flight tshark instances already saturate fork/exec
    // on typical dev machines. Saves us from spawning 16+ threads on big
    // CPUs for what is fundamentally an I/O-bound test.
    const cpu_count = std.Thread.getCpuCount() catch 4;
    // Honor SNAPSHOT_WORKERS=N env var to override the worker count (mostly
    // useful for measuring serial-vs-parallel scaling).
    const env_override: ?usize = blk: {
        const raw = std.c.getenv("SNAPSHOT_WORKERS") orelse break :blk null;
        const v = std.mem.sliceTo(raw, 0);
        break :blk std.fmt.parseInt(usize, v, 10) catch null;
    };
    const n_workers = env_override orelse @max(@as(usize, 1), @min(cpu_count, 8));
    const threads = try gpa.alloc(std.Thread, n_workers - 1);
    defer gpa.free(threads);

    for (threads) |*t| t.* = try std.Thread.spawn(.{}, worker, .{&shared});
    // Run one worker on the main thread to make the common case
    // (cpu_count == 1 or short queue) skip thread spawn overhead.
    worker(&shared);
    for (threads) |t| t.join();

    // Single pass to surface the first failure and count totals.
    var failures: usize = 0;
    var first_idx: ?usize = null;
    for (slots, 0..) |slot, i| {
        if (slot.failure != null) {
            failures += 1;
            if (first_idx == null) first_idx = i;
        }
    }
    if (failures != 0) {
        if (first_idx) |i| std.debug.print("{s}", .{slots[i].failure.?});
        std.debug.print("[snapshot] {d}/{d} fixtures failed\n", .{ failures, slots.len });
        return error.SnapshotMismatch;
    }
}

fn worker(shared: *Shared) void {
    const gpa = shared.gpa;
    const io = shared.io;

    // Each worker opens its own handle on the snapshots dir so they don't
    // contend on a shared `Io.Dir.Reader` cursor.
    var snapshots_dir = Io.Dir.cwd().openDir(io, shared.snapshots_dir_path, .{}) catch return;
    defer snapshots_dir.close(io);

    while (true) {
        const i = shared.next.fetchAdd(1, .acq_rel);
        if (i >= shared.names.len) return;
        runOne(gpa, io, shared.pcap_dir, snapshots_dir, shared.names[i], &shared.slots[i]) catch |err| {
            // Convert unexpected errors to a recorded failure rather than
            // aborting the whole test run.
            const msg = std.fmt.allocPrint(
                gpa,
                "[snapshot] {s}: worker error {s}\n",
                .{ shared.names[i], @errorName(err) },
            ) catch return;
            shared.slots[i].failure = msg;
        };
    }
}

fn runOne(
    gpa: std.mem.Allocator,
    io: Io,
    pcap_dir_path: []const u8,
    snapshots_dir: Io.Dir,
    name: []const u8,
    slot: *Slot,
) !void {
    const pcap_path = try std.fs.path.join(gpa, &.{ pcap_dir_path, name });
    defer gpa.free(pcap_path);

    const snap_name = try std.fmt.allocPrint(gpa, "{s}.yaml", .{name});
    defer gpa.free(snap_name);

    const expected = try snapshots_dir.readFileAlloc(io, snap_name, gpa, .limited(1 * 1024 * 1024));
    defer gpa.free(expected);

    const result = try std.process.run(gpa, io, .{
        .argv = &.{ build_options.exe_path, pcap_path },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    const exit_ok = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };

    if (!exit_ok or !std.mem.eql(u8, result.stdout, expected)) {
        slot.failure = try std.fmt.allocPrint(
            gpa,
            "[snapshot] mismatch in {s}\n--- expected ---\n{s}\n--- got (term={any}) ---\n{s}\n--- stderr ---\n{s}\n",
            .{ name, expected, result.term, result.stdout, result.stderr },
        );
    }
}

fn isPcapName(name: []const u8) bool {
    // Matches the upstream insta glob `pcap/*.pcap*`: anything containing
    // `.pcap` (covers `.pcap` and `.pcapng`). Excludes `.notest.cap` because
    // it doesn't contain `.pcap`.
    return std.mem.indexOf(u8, name, ".pcap") != null;
}

fn ltStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}
