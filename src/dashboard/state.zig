const std = @import("std");
const net = std.net;
const Explorer = @import("../explorer.zig").Explorer;
const ws = @import("ws.zig");

pub const DashboardConfig = struct {
    port: u16 = 8080,
    bind_address: []const u8 = "127.0.0.1",
    max_ws_clients: usize = 100,
    update_interval_ms: u32 = 2000,
    read_only: bool = false,
    disable_topology: bool = false,
    disable_map: bool = false,
    state_file: ?[]const u8 = null,
};

pub const BlockRecord = struct {
    hash: [64]u8,
    time: i64,
    height: i32,
};

pub const PeerRecord = struct {
    addr: []const u8,
    services: u64,
    quality_score: ?u8,
    latency_ms: ?u64,
    ever_connected: bool,
    reconnect_count: u32,
};

pub const BanRecord = struct {
    addr: []const u8,
    expiry_time: i64,
    reason: []const u8,
};

pub const BanEntry = BanRecord; // TODO: remove alias once all callers use BanRecord

pub const PersistentState = struct {
    version: u32 = 1,
    peers: []PeerRecord = &[_]PeerRecord{},
    bans: []BanRecord = &[_]BanRecord{},
    blocks: []BlockRecord = &[_]BlockRecord{},
    total_bytes_in: u64 = 0,
    total_bytes_out: u64 = 0,
    total_msgs_in: u64 = 0,
    total_msgs_out: u64 = 0,
    total_session_time: i64 = 0,

    pub fn load(allocator: std.mem.Allocator, path: []const u8) ?PersistentState {
        const file = std.fs.cwd().openFile(path, .{}) catch return null;
        defer file.close();
        const content = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return null;
        defer allocator.free(content);
        const parsed = std.json.parseFromSlice(PersistentState, allocator, content, .{ .allocate = .alloc_always }) catch return null;
        return parsed.value;
    }

    pub fn save(self: PersistentState, allocator: std.mem.Allocator, path: []const u8) bool {
        var json = std.ArrayList(u8).empty;
        defer json.deinit(allocator);
        const writer = json.writer(allocator);

        writer.writeAll("{\"version\":") catch return false;
        writer.print("{d}", .{self.version}) catch return false;

        writer.writeAll(",\"peers\":[") catch return false;
        for (self.peers, 0..) |peer, i| {
            if (i > 0) writer.writeByte(',') catch return false;
            writer.print("{{\"addr\":\"{s}\",\"services\":{d},\"quality_score\":", .{ peer.addr, peer.services }) catch return false;
            if (peer.quality_score) |qs| {
                writer.print("{d}", .{qs}) catch return false;
            } else {
                writer.writeAll("null") catch return false;
            }
            writer.writeAll(",\"latency_ms\":") catch return false;
            if (peer.latency_ms) |lat| {
                writer.print("{d}", .{lat}) catch return false;
            } else {
                writer.writeAll("null") catch return false;
            }
            writer.print(",\"ever_connected\":{},\"reconnect_count\":{d}}}", .{ peer.ever_connected, peer.reconnect_count }) catch return false;
        }

        writer.writeAll("],\"bans\":[") catch return false;
        for (self.bans, 0..) |ban, i| {
            if (i > 0) writer.writeByte(',') catch return false;
            writer.print("{{\"addr\":\"{s}\",\"expiry_time\":{d},\"reason\":\"{s}\"}}", .{ ban.addr, ban.expiry_time, ban.reason }) catch return false;
        }

        writer.writeAll("],\"blocks\":[") catch return false;
        for (self.blocks, 0..) |block, i| {
            if (i > 0) writer.writeByte(',') catch return false;
            writer.print("{{\"hash\":\"{s}\",\"time\":{d},\"height\":{d}}}", .{ block.hash, block.time, block.height }) catch return false;
        }

        writer.print("],\"total_bytes_in\":{d},\"total_bytes_out\":{d},\"total_msgs_in\":{d},\"total_msgs_out\":{d},\"total_session_time\":{d}}}", .{
            self.total_bytes_in,
            self.total_bytes_out,
            self.total_msgs_in,
            self.total_msgs_out,
            self.total_session_time,
        }) catch return false;

        const file = std.fs.cwd().createFile(path, .{}) catch return false;
        defer file.close();
        file.writeAll(json.items) catch return false;
        return true;
    }

    pub fn deinit(self: *PersistentState, allocator: std.mem.Allocator) void {
        for (self.peers) |peer| allocator.free(peer.addr);
        allocator.free(self.peers);
        for (self.bans) |ban| {
            allocator.free(ban.addr);
            allocator.free(ban.reason);
        }
        allocator.free(self.bans);
        allocator.free(self.blocks);
    }
};

pub const DashboardState = struct {
    allocator: std.mem.Allocator,
    explorer: *Explorer,
    config: DashboardConfig,
    ws_clients: std.ArrayList(net.Stream),
    ws_mutex: std.Thread.Mutex,
    last_node_count: usize,
    last_mempool_count: usize,
    last_broadcast_time: i64,
    banned_peers: std.StringHashMap(BanEntry),
    ban_mutex: std.Thread.Mutex,
    block_history: std.ArrayList(BlockRecord),
    cumulative_bytes_in: u64,
    cumulative_bytes_out: u64,
    cumulative_msgs_in: u64,
    cumulative_msgs_out: u64,
    cumulative_session_time: i64,
    last_save_time: i64,
    save_thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator, explorer: *Explorer, config: DashboardConfig) !*DashboardState {
        const self = try allocator.create(DashboardState);
        self.* = .{
            .allocator = allocator,
            .explorer = explorer,
            .config = config,
            .ws_clients = std.ArrayList(net.Stream).empty,
            .ws_mutex = .{},
            .last_node_count = 0,
            .last_mempool_count = 0,
            .last_broadcast_time = 0,
            .banned_peers = std.StringHashMap(BanEntry).init(allocator),
            .ban_mutex = .{},
            .block_history = std.ArrayList(BlockRecord).empty,
            .cumulative_bytes_in = 0,
            .cumulative_bytes_out = 0,
            .cumulative_msgs_in = 0,
            .cumulative_msgs_out = 0,
            .cumulative_session_time = 0,
            .last_save_time = std.time.timestamp(),
            .save_thread = null,
        };
        if (config.state_file) |path| self.loadState(path);
        return self;
    }

    pub fn deinit(self: *DashboardState) void {
        if (self.config.state_file) |path| self.saveState(path);
        if (self.save_thread) |thread| thread.join();
        self.ws_clients.deinit(self.allocator);
        var iter = self.banned_peers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.addr);
            self.allocator.free(entry.value_ptr.reason);
        }
        self.banned_peers.deinit();
        self.block_history.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn addBlock(self: *DashboardState, hash: [64]u8, time: i64, height: i32) void {
        self.block_history.append(self.allocator, .{ .hash = hash, .time = time, .height = height }) catch return;
        if (self.block_history.items.len > 100) _ = self.block_history.orderedRemove(0);
    }

    pub fn loadState(self: *DashboardState, path: []const u8) void {
        var state = PersistentState.load(self.allocator, path) orelse return;
        defer state.deinit(self.allocator);

        self.cumulative_bytes_in = state.total_bytes_in;
        self.cumulative_bytes_out = state.total_bytes_out;
        self.cumulative_msgs_in = state.total_msgs_in;
        self.cumulative_msgs_out = state.total_msgs_out;
        self.cumulative_session_time = state.total_session_time;

        for (state.bans) |ban| self.loadBanEntry(ban);
        for (state.blocks) |block| self.block_history.append(self.allocator, block) catch {};

        std.debug.print("Loaded state: {d} peers, {d} bans, {d} blocks\n", .{
            state.peers.len, state.bans.len, state.blocks.len,
        });
    }

    fn loadBanEntry(self: *DashboardState, ban: BanRecord) void {
        if (self.banned_peers.contains(ban.addr)) return;
        const key = self.allocator.dupe(u8, ban.addr) catch return;
        errdefer self.allocator.free(key);
        const addr = self.allocator.dupe(u8, ban.addr) catch return;
        errdefer self.allocator.free(addr);
        const reason = self.allocator.dupe(u8, ban.reason) catch return;
        errdefer self.allocator.free(reason);
        self.banned_peers.put(key, .{ .addr = addr, .expiry_time = ban.expiry_time, .reason = reason }) catch {};
    }

    pub fn saveState(self: *DashboardState, path: []const u8) void {
        self.explorer.mutex.lock();
        defer self.explorer.mutex.unlock();
        self.ban_mutex.lock();
        defer self.ban_mutex.unlock();

        var peers = self.collectPeerRecords();
        defer self.freePeerRecords(&peers);
        var bans = self.collectBanRecords();
        defer self.freeBanRecords(&bans);
        const stats = self.computeTotalStats();

        const pstate = PersistentState{
            .version = 1,
            .peers = peers.items,
            .bans = bans.items,
            .blocks = self.block_history.items,
            .total_bytes_in = stats.bytes_in,
            .total_bytes_out = stats.bytes_out,
            .total_msgs_in = stats.msgs_in,
            .total_msgs_out = stats.msgs_out,
            .total_session_time = stats.session_time,
        };

        if (pstate.save(self.allocator, path)) self.last_save_time = std.time.timestamp();
    }

    fn collectPeerRecords(self: *DashboardState) std.ArrayList(PeerRecord) {
        var peers = std.ArrayList(PeerRecord).empty;
        var idx: usize = 0;
        for (self.explorer.known_nodes.items) |node| {
            idx += 1;
            const addr_buf = node.format();
            const addr = self.allocator.dupe(u8, std.mem.sliceTo(&addr_buf, ' ')) catch continue;
            const meta = self.explorer.node_metadata.get(idx);
            peers.append(self.allocator, .{
                .addr = addr,
                .services = node.services,
                .quality_score = null,
                .latency_ms = if (meta) |m| m.latency_ms else null,
                .ever_connected = if (meta) |m| m.ever_connected else false,
                .reconnect_count = 0,
            }) catch self.allocator.free(addr);
        }
        return peers;
    }

    fn freePeerRecords(self: *DashboardState, peers: *std.ArrayList(PeerRecord)) void {
        for (peers.items) |p| self.allocator.free(p.addr);
        peers.deinit(self.allocator);
    }

    fn collectBanRecords(self: *DashboardState) std.ArrayList(BanRecord) {
        var bans = std.ArrayList(BanRecord).empty;
        var iter = self.banned_peers.iterator();
        while (iter.next()) |entry| {
            const addr = self.allocator.dupe(u8, entry.value_ptr.addr) catch continue;
            const reason = self.allocator.dupe(u8, entry.value_ptr.reason) catch {
                self.allocator.free(addr);
                continue;
            };
            bans.append(self.allocator, .{ .addr = addr, .expiry_time = entry.value_ptr.expiry_time, .reason = reason }) catch {
                self.allocator.free(addr);
                self.allocator.free(reason);
            };
        }
        return bans;
    }

    fn freeBanRecords(self: *DashboardState, bans: *std.ArrayList(BanRecord)) void {
        for (bans.items) |b| {
            self.allocator.free(b.addr);
            self.allocator.free(b.reason);
        }
        bans.deinit(self.allocator);
    }

    const TotalStats = struct { bytes_in: u64, bytes_out: u64, msgs_in: u64, msgs_out: u64, session_time: i64 };

    fn computeTotalStats(self: *DashboardState) TotalStats {
        return TotalStats{
            .bytes_in = self.cumulative_bytes_in,
            .bytes_out = self.cumulative_bytes_out,
            .msgs_in = self.cumulative_msgs_in,
            .msgs_out = self.cumulative_msgs_out,
            .session_time = self.cumulative_session_time,
        };
    }

    pub fn clearState(self: *DashboardState) void {
        self.ban_mutex.lock();
        var iter = self.banned_peers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.addr);
            self.allocator.free(entry.value_ptr.reason);
        }
        self.banned_peers.clearRetainingCapacity();
        self.ban_mutex.unlock();

        self.block_history.clearRetainingCapacity();
        self.cumulative_bytes_in = 0;
        self.cumulative_bytes_out = 0;
        self.cumulative_msgs_in = 0;
        self.cumulative_msgs_out = 0;
        self.cumulative_session_time = 0;

        if (self.config.state_file) |path| std.fs.cwd().deleteFile(path) catch {};
    }

    pub fn isBanned(self: *DashboardState, addr: []const u8) bool {
        self.ban_mutex.lock();
        defer self.ban_mutex.unlock();
        if (self.banned_peers.get(addr)) |entry| {
            if (entry.expiry_time == 0) return true;
            if (entry.expiry_time > std.time.timestamp()) return true;
            const key = self.banned_peers.fetchRemove(addr).?.key;
            self.allocator.free(key);
            self.allocator.free(entry.addr);
            self.allocator.free(entry.reason);
        }
        return false;
    }

    pub fn registerClient(self: *DashboardState, stream: net.Stream) bool {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        if (self.ws_clients.items.len >= self.config.max_ws_clients) return false;
        self.ws_clients.append(self.allocator, stream) catch return false;
        return true;
    }

    pub fn unregisterClient(self: *DashboardState, stream: net.Stream) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        for (self.ws_clients.items, 0..) |s, i| {
            if (s.handle == stream.handle) {
                _ = self.ws_clients.swapRemove(i);
                break;
            }
        }
    }

    pub fn broadcastJson(self: *DashboardState, json: []const u8) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        var i: usize = 0;
        while (i < self.ws_clients.items.len) {
            ws.writeText(self.ws_clients.items[i], json) catch {
                _ = self.ws_clients.swapRemove(i);
                continue;
            };
            i += 1;
        }
    }
};
