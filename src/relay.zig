// Relay.zig - Transaction relay and broadcast module
// Named after the relay stations that rapidly transmitted messages across vast distances

const std = @import("std");
const yam = @import("root.zig");
const Courier = @import("courier.zig").Courier;

/// Timing strategy for transaction broadcast
pub const TimingStrategy = enum {
    /// Send to all peers simultaneously (fastest propagation)
    simultaneous,
    /// Stagger sends with random delays (better privacy)
    staggered_random,
};

/// Options for broadcast operation
pub const BroadcastOptions = struct {
    strategy: TimingStrategy = .simultaneous,
    min_delay_ms: u32 = 50,
    max_delay_ms: u32 = 500,
    max_peers: ?usize = null, // limit broadcasts to first N connected peers
};

/// Result of a broadcast attempt to a single peer
pub const BroadcastReport = struct {
    peer: yam.PeerInfo,
    success: bool,
    elapsed_ms: u64,
};

/// Result of broadcasting to multiple peers
pub const BroadcastResult = struct {
    reports: []BroadcastReport,
    success_count: usize,

    pub fn deinit(self: *BroadcastResult, allocator: std.mem.Allocator) void {
        allocator.free(self.reports);
    }
};

/// Context passed to each connection worker thread
const ConnectContext = struct {
    courier: *Courier,
    line_num: usize,
    total_lines: usize,
    done_count: *std.atomic.Value(usize),
    success_count: *std.atomic.Value(usize),
    target: usize,
};

/// Worker function for parallel peer connection
fn connectWorker(ctx: ConnectContext) void {
    defer _ = ctx.done_count.fetchAdd(1, .release);

    const addr_str = ctx.courier.peer.format();
    const addr = std.mem.sliceTo(&addr_str, ' ');

    // Calculate how many lines to move up to reach our line
    // Lines are printed top-to-bottom, cursor ends at bottom
    const lines_up = ctx.total_lines - ctx.line_num;

    // Check if target already reached before attempting connection
    if (ctx.success_count.load(.acquire) >= ctx.target) {
        std.debug.print("\x1b[{d}A\r{s}: SKIPPED\x1b[K\x1b[{d}B\r", .{
            lines_up,
            addr,
            lines_up,
        });
        return;
    }

    ctx.courier.connect() catch |err| {
        // Move up, update with FAILED, move back down
        std.debug.print("\x1b[{d}A\r{s}: FAILED ({s})\x1b[K\x1b[{d}B\r", .{
            lines_up,
            addr,
            @errorName(err),
            lines_up,
        });
        return;
    };

    _ = ctx.success_count.fetchAdd(1, .release);

    // Move up, update with OK, move back down
    std.debug.print("\x1b[{d}A\r{s}: OK\x1b[K\x1b[{d}B\r", .{
        lines_up,
        addr,
        lines_up,
    });
}

/// Shared state for connection threads
const ConnectState = struct {
    done_count: std.atomic.Value(usize),
    success_count: std.atomic.Value(usize),
};

/// Relay manages connections to multiple peers for transaction broadcast
pub const Relay = struct {
    couriers: []Courier,
    allocator: std.mem.Allocator,
    pending_threads: ?[]?std.Thread = null,
    connect_state: ?*ConnectState = null,

    pub fn init(peers: []const yam.PeerInfo, allocator: std.mem.Allocator) !Relay {
        const couriers = try allocator.alloc(Courier, peers.len);
        errdefer allocator.free(couriers);

        for (couriers, peers) |*courier, peer| {
            courier.* = Courier.init(peer, allocator);
        }

        return .{
            .couriers = couriers,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Relay) void {
        // Join any pending connection threads before freeing couriers
        if (self.pending_threads) |threads| {
            for (threads) |maybe_thread| {
                if (maybe_thread) |thread| thread.join();
            }
            self.allocator.free(threads);
        }
        if (self.connect_state) |state| {
            self.allocator.destroy(state);
        }
        for (self.couriers) |*courier| {
            courier.deinit();
        }
        self.allocator.free(self.couriers);
    }

    /// Connect to peers in parallel, performing handshake
    /// Returns early once target connections are established
    /// Returns the number of successful connections
    pub fn connectAll(self: *Relay, target: usize) usize {
        const n = self.couriers.len;
        if (n == 0) return 0;

        // Print initial status for all peers
        for (self.couriers) |*courier| {
            const addr_str = courier.peer.format();
            std.debug.print("{s}: Connecting...\n", .{std.mem.sliceTo(&addr_str, ' ')});
        }

        // Allocate thread handles (stored in Relay, joined in deinit)
        const threads = self.allocator.alloc(?std.Thread, n) catch {
            // Fallback to sequential if allocation fails
            return self.connectAllSequential(target);
        };
        self.pending_threads = threads;

        // Heap-allocate atomic counters (freed in deinit, after threads joined)
        const state = self.allocator.create(ConnectState) catch {
            self.allocator.free(threads);
            self.pending_threads = null;
            return self.connectAllSequential(target);
        };
        state.* = .{
            .done_count = std.atomic.Value(usize).init(0),
            .success_count = std.atomic.Value(usize).init(0),
        };
        self.connect_state = state;

        // Spawn a thread for each courier
        for (self.couriers, 0..) |*courier, i| {
            const ctx = ConnectContext{
                .courier = courier,
                .line_num = i,
                .total_lines = n,
                .done_count = &state.done_count,
                .success_count = &state.success_count,
                .target = target,
            };
            threads[i] = std.Thread.spawn(.{}, connectWorker, .{ctx}) catch null;
        }

        // Poll until target reached or all threads done
        while (true) {
            const done = state.done_count.load(.acquire);
            const success = state.success_count.load(.acquire);

            if (success >= target or done >= n) break;

            std.Thread.sleep(50 * std.time.ns_per_ms);
        }

        // Return immediately - threads will be joined in deinit()
        return state.success_count.load(.acquire);
    }

    /// Sequential fallback for connectAll
    fn connectAllSequential(self: *Relay, target: usize) usize {
        var connected: usize = 0;
        for (self.couriers) |*courier| {
            if (connected >= target) break;
            courier.connect() catch continue;
            connected += 1;
        }
        return connected;
    }

    /// Broadcast a transaction to connected peers
    /// If max_peers is set, stops after that many successful broadcasts
    pub fn broadcastTx(self: *Relay, tx_bytes: []const u8, options: BroadcastOptions) !BroadcastResult {
        var reports_list: std.ArrayList(BroadcastReport) = .empty;
        errdefer reports_list.deinit(self.allocator);

        var success_count: usize = 0;

        // Initialize RNG for staggered timing
        var rng_seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&rng_seed));
        var rng = std.Random.DefaultPrng.init(rng_seed);

        var broadcasts_attempted: usize = 0;
        for (self.couriers) |*courier| {
            // Check if we've reached max_peers successful broadcasts
            if (options.max_peers) |max| {
                if (success_count >= max) break;
            }

            // Skip unconnected peers
            if (!courier.connected) continue;

            // Apply delay for staggered strategy (after first broadcast)
            if (options.strategy == .staggered_random and broadcasts_attempted > 0) {
                const delay = rng.random().intRangeAtMost(u32, options.min_delay_ms, options.max_delay_ms);
                std.Thread.sleep(@as(u64, delay) * std.time.ns_per_ms);
            }

            broadcasts_attempted += 1;
            const start = std.time.milliTimestamp();
            var report = BroadcastReport{
                .peer = courier.peer,
                .success = false,
                .elapsed_ms = 0,
            };

            courier.sendTx(tx_bytes) catch |err| {
                std.debug.print("Failed to send tx to peer: {s}\n", .{@errorName(err)});
                report.elapsed_ms = @intCast(std.time.milliTimestamp() - start);
                try reports_list.append(self.allocator, report);
                continue;
            };

            report.success = true;
            success_count += 1;
            report.elapsed_ms = @intCast(std.time.milliTimestamp() - start);
            try reports_list.append(self.allocator, report);
        }

        return .{
            .reports = try reports_list.toOwnedSlice(self.allocator),
            .success_count = success_count,
        };
    }
};

/// Print a formatted broadcast report
pub fn printBroadcastReport(reports: []const BroadcastReport, allocator: std.mem.Allocator) void {
    _ = allocator;

    std.debug.print("\n=== Broadcast Report ===\n", .{});

    for (reports) |report| {
        const addr_str = report.peer.format();
        const status = if (report.success) "SUCCESS" else "FAILED";

        std.debug.print("{s}: {s} ({d}ms)\n", .{
            std.mem.sliceTo(&addr_str, ' '),
            status,
            report.elapsed_ms,
        });
    }
}
