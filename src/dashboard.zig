const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;
const yam = @import("root.zig");
const scout = @import("scout.zig");
const Explorer = @import("explorer.zig").Explorer;

const index_html = @embedFile("dashboard.html");

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
        for (self.peers) |peer| {
            allocator.free(peer.addr);
        }
        allocator.free(self.peers);
        for (self.bans) |ban| {
            allocator.free(ban.addr);
            allocator.free(ban.reason);
        }
        allocator.free(self.bans);
        allocator.free(self.blocks);
    }
};

pub const BanEntry = struct {
    addr: []const u8,
    expiry_time: i64,
    reason: []const u8,
};

pub const DashboardState = struct {
    allocator: std.mem.Allocator,
    explorer: *Explorer,
    config: DashboardConfig,
    ws_clients: std.ArrayList(*WsHandler),
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

    pub const WebsocketHandler = WsHandler;

    pub fn init(allocator: std.mem.Allocator, explorer: *Explorer, config: DashboardConfig) !*DashboardState {
        const self = try allocator.create(DashboardState);
        self.* = .{
            .allocator = allocator,
            .explorer = explorer,
            .config = config,
            .ws_clients = std.ArrayList(*WsHandler).empty,
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
        if (config.state_file) |path| {
            self.loadState(path);
        }
        return self;
    }

    pub fn deinit(self: *DashboardState) void {
        if (self.config.state_file) |path| {
            self.saveState(path);
        }
        if (self.save_thread) |thread| {
            thread.join();
        }
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
        if (self.block_history.items.len > 100) {
            _ = self.block_history.orderedRemove(0);
        }
    }

    fn loadState(self: *DashboardState, path: []const u8) void {
        var state = PersistentState.load(self.allocator, path) orelse return;
        defer state.deinit(self.allocator);

        self.cumulative_bytes_in = state.total_bytes_in;
        self.cumulative_bytes_out = state.total_bytes_out;
        self.cumulative_msgs_in = state.total_msgs_in;
        self.cumulative_msgs_out = state.total_msgs_out;
        self.cumulative_session_time = state.total_session_time;

        for (state.bans) |ban| {
            const key = self.allocator.dupe(u8, ban.addr) catch continue;
            const addr = self.allocator.dupe(u8, ban.addr) catch {
                self.allocator.free(key);
                continue;
            };
            const reason = self.allocator.dupe(u8, ban.reason) catch {
                self.allocator.free(key);
                self.allocator.free(addr);
                continue;
            };
            self.banned_peers.put(key, .{ .addr = addr, .expiry_time = ban.expiry_time, .reason = reason }) catch {
                self.allocator.free(key);
                self.allocator.free(addr);
                self.allocator.free(reason);
            };
        }

        for (state.blocks) |block| {
            self.block_history.append(self.allocator, block) catch {};
        }

        std.debug.print("Loaded state: {d} peers, {d} bans, {d} blocks\n", .{ state.peers.len, state.bans.len, state.blocks.len });
    }

    fn saveState(self: *DashboardState, path: []const u8) void {
        self.explorer.mutex.lock();
        defer self.explorer.mutex.unlock();
        self.ban_mutex.lock();
        defer self.ban_mutex.unlock();

        var peers = std.ArrayList(PeerRecord).empty;
        defer {
            for (peers.items) |p| self.allocator.free(p.addr);
            peers.deinit(self.allocator);
        }

        var idx: usize = 0;
        for (self.explorer.known_nodes.items) |node| {
            idx += 1;
            const addr_buf = node.format();
            const addr = self.allocator.dupe(u8, std.mem.sliceTo(&addr_buf, ' ')) catch continue;
            const meta = self.explorer.node_metadata.get(idx);
            peers.append(self.allocator, .{
                .addr = addr,
                .services = node.services,
                .quality_score = if (meta) |m| m.qualityScore() else null,
                .latency_ms = if (meta) |m| m.latency_ms else null,
                .ever_connected = if (meta) |m| m.ever_connected else false,
                .reconnect_count = if (meta) |m| m.reconnect_count else 0,
            }) catch {
                self.allocator.free(addr);
            };
        }

        var bans = std.ArrayList(BanRecord).empty;
        defer {
            for (bans.items) |b| {
                self.allocator.free(b.addr);
                self.allocator.free(b.reason);
            }
            bans.deinit(self.allocator);
        }

        var ban_iter = self.banned_peers.iterator();
        while (ban_iter.next()) |entry| {
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

        var total_bytes_in: u64 = self.cumulative_bytes_in;
        var total_bytes_out: u64 = self.cumulative_bytes_out;
        var total_msgs_in: u64 = self.cumulative_msgs_in;
        var total_msgs_out: u64 = self.cumulative_msgs_out;
        var meta_iter = self.explorer.node_metadata.valueIterator();
        while (meta_iter.next()) |meta| {
            total_bytes_in += meta.bytes_in;
            total_bytes_out += meta.bytes_out;
            total_msgs_in += meta.msgs_in;
            total_msgs_out += meta.msgs_out;
        }

        const session_time = std.time.timestamp() - self.explorer.session_start;
        const total_session = self.cumulative_session_time + session_time;

        const state = PersistentState{
            .version = 1,
            .peers = peers.items,
            .bans = bans.items,
            .blocks = self.block_history.items,
            .total_bytes_in = total_bytes_in,
            .total_bytes_out = total_bytes_out,
            .total_msgs_in = total_msgs_in,
            .total_msgs_out = total_msgs_out,
            .total_session_time = total_session,
        };

        if (state.save(self.allocator, path)) {
            self.last_save_time = std.time.timestamp();
        }
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

        if (self.config.state_file) |path| {
            std.fs.cwd().deleteFile(path) catch {};
        }
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

    pub fn registerClient(self: *DashboardState, client: *WsHandler) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        self.ws_clients.append(self.allocator, client) catch {};
    }

    pub fn unregisterClient(self: *DashboardState, client: *WsHandler) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        for (self.ws_clients.items, 0..) |c, i| {
            if (c == client) {
                _ = self.ws_clients.swapRemove(i);
                break;
            }
        }
    }

    pub fn broadcastJson(self: *DashboardState, json: []const u8) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        for (self.ws_clients.items) |client| {
            client.conn.writeText(json) catch {};
        }
    }
};

pub const WsHandler = struct {
    conn: *websocket.Conn,
    state: *DashboardState,

    pub fn init(conn: *websocket.Conn, ctx: *DashboardState) !WsHandler {
        return .{ .conn = conn, .state = ctx };
    }

    pub fn afterInit(self: *WsHandler) !void {
        self.state.registerClient(self);
        if (buildStatusJson(self.state)) |json| {
            defer self.state.allocator.free(json);
            try self.conn.writeText(json);
        } else |_| {}
    }

    pub fn clientMessage(self: *WsHandler, _: []const u8) !void {
        if (buildStatusJson(self.state)) |json| {
            defer self.state.allocator.free(json);
            try self.conn.writeText(json);
        } else |_| {}
    }

    pub fn close(self: *WsHandler) void {
        self.state.unregisterClient(self);
    }
};

pub const Dashboard = struct {
    allocator: std.mem.Allocator,
    server: httpz.Server(*DashboardState),
    state: *DashboardState,
    explorer: *Explorer,
    update_thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator, config: DashboardConfig) !*Dashboard {
        const explorer = try Explorer.init(allocator);
        errdefer explorer.deinit();

        const state = try DashboardState.init(allocator, explorer, config);
        errdefer state.deinit();

        var server = try httpz.Server(*DashboardState).init(allocator, .{
            .port = config.port,
            .address = config.bind_address,
        }, state);
        errdefer server.deinit();

        var router = try server.router(.{});
        router.get("/", serveIndex, .{});
        router.get("/ws", serveWebsocket, .{});
        router.get("/api/v1/status", handleApiStatus, .{});
        router.get("/api/v1/nodes", handleApiNodes, .{});
        router.get("/api/v1/mempool", handleApiMempool, .{});
        router.get("/api/v1/blocks", handleApiBlocks, .{});
        if (!config.read_only) {
            router.post("/api/peer/disconnect", handleDisconnect, .{});
            router.post("/api/peer/ban", handleBan, .{});
            router.post("/api/peer/unban", handleUnban, .{});
            router.get("/api/peers/banned", handleBannedList, .{});
            router.post("/api/state/clear", handleClearState, .{});
        }

        const self = try allocator.create(Dashboard);
        self.* = .{
            .allocator = allocator,
            .server = server,
            .state = state,
            .explorer = explorer,
            .update_thread = null,
        };
        return self;
    }

    pub fn deinit(self: *Dashboard) void {
        self.explorer.should_stop.store(true, .release);
        if (self.update_thread) |thread| {
            thread.join();
        }
        self.server.deinit();
        self.state.deinit();
        self.explorer.deinit();
        self.allocator.destroy(self);
    }

    pub fn run(self: *Dashboard) !void {
        std.debug.print("Dashboard starting on http://{s}:{d}\n", .{ self.state.config.bind_address, self.state.config.port });
        if (self.state.config.state_file) |path| {
            std.debug.print("State file: {s}\n", .{path});
        }
        std.debug.print("Press Ctrl+C to stop\n\n", .{});

        try self.discoverAndConnect();
        self.update_thread = try std.Thread.spawn(.{}, updateBroadcaster, .{self.state});
        if (self.state.config.state_file != null) {
            self.state.save_thread = try std.Thread.spawn(.{}, stateSaver, .{self.state});
        }
        try self.server.listen();
    }

    fn discoverAndConnect(self: *Dashboard) !void {
        std.debug.print("Discovering peers via DNS seeds...\n", .{});
        var node_list = try scout.discoverPeers(self.allocator);
        defer node_list.deinit(self.allocator);

        std.debug.print("Found {d} peers from DNS seeds\n", .{node_list.items.len});

        for (node_list.items) |node| {
            const key = try self.formatNodeKey(node);
            if (!self.explorer.seen_nodes.contains(key)) {
                try self.explorer.seen_nodes.put(key, {});
                try self.explorer.known_nodes.append(self.allocator, node);
                const idx = self.explorer.known_nodes.items.len;
                try self.explorer.unconnected_nodes.put(idx, {});
            } else {
                self.allocator.free(key);
            }
        }

        std.debug.print("Starting network manager thread...\n", .{});
        self.explorer.manager_thread = try std.Thread.spawn(.{}, Explorer.managerThread, .{self.explorer});

        const connect_count = @min(20, self.explorer.known_nodes.items.len);
        std.debug.print("Connecting to {d} peers...\n", .{connect_count});

        for (1..connect_count + 1) |idx| {
            self.explorer.mutex.lock();
            self.explorer.pending_commands.append(self.allocator, .{ .connect = idx }) catch {};
            _ = self.explorer.unconnected_nodes.remove(idx);
            self.explorer.mutex.unlock();
        }
    }

    fn formatNodeKey(self: *Dashboard, node: yam.PeerInfo) ![]u8 {
        const addr_str = node.format();
        return try self.allocator.dupe(u8, std.mem.sliceTo(&addr_str, ' '));
    }
};

fn serveIndex(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = httpz.ContentType.HTML;
    const has_state_file = ctx.config.state_file != null;
    const config_script = std.fmt.allocPrint(ctx.allocator,
        \\<script>window.DASHBOARD_CONFIG={{readOnly:{},disableTopology:{},disableMap:{},updateInterval:{d},hasStateFile:{}}};</script>
    , .{
        ctx.config.read_only,
        ctx.config.disable_topology,
        ctx.config.disable_map,
        ctx.config.update_interval_ms,
        has_state_file,
    }) catch {
        res.body = index_html;
        return;
    };
    defer ctx.allocator.free(config_script);
    // Insert config script after <head> tag to produce valid HTML
    const head_tag = "<head>";
    const head_pos = std.mem.indexOf(u8, index_html, head_tag) orelse {
        res.body = index_html;
        return;
    };
    const insert_pos = head_pos + head_tag.len;
    const html = std.fmt.allocPrint(ctx.allocator, "{s}{s}{s}", .{
        index_html[0..insert_pos],
        config_script,
        index_html[insert_pos..],
    }) catch {
        res.body = index_html;
        return;
    };
    res.body = html;
}

fn serveWebsocket(ctx: *DashboardState, req: *httpz.Request, res: *httpz.Response) !void {
    _ = httpz.upgradeWebsocket(WsHandler, req, res, ctx) catch {
        res.status = 400;
        res.body = "invalid websocket handshake";
    };
}

fn handleDisconnect(ctx: *DashboardState, req: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .JSON;
    const body = req.body() orelse {
        res.status = 400;
        res.body = "{\"error\":\"missing body\"}";
        return;
    };
    const parsed = std.json.parseFromSlice(struct { index: usize }, ctx.allocator, body, .{}) catch {
        res.status = 400;
        res.body = "{\"error\":\"invalid json\"}";
        return;
    };
    defer parsed.deinit();
    const node_index = parsed.value.index;
    ctx.explorer.mutex.lock();
    defer ctx.explorer.mutex.unlock();
    if (ctx.explorer.connections.get(node_index)) |conn| {
        std.posix.close(conn.socket);
        _ = ctx.explorer.connections.remove(node_index);
        res.body = "{\"success\":true}";
    } else {
        res.status = 404;
        res.body = "{\"error\":\"peer not found\"}";
    }
}

fn handleBan(ctx: *DashboardState, req: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .JSON;
    const body = req.body() orelse {
        res.status = 400;
        res.body = "{\"error\":\"missing body\"}";
        return;
    };
    const parsed = std.json.parseFromSlice(struct { addr: []const u8, duration: i64 }, ctx.allocator, body, .{}) catch {
        res.status = 400;
        res.body = "{\"error\":\"invalid json\"}";
        return;
    };
    defer parsed.deinit();
    const addr = try ctx.allocator.dupe(u8, parsed.value.addr);
    const key = try ctx.allocator.dupe(u8, parsed.value.addr);
    const expiry: i64 = if (parsed.value.duration == 0) 0 else std.time.timestamp() + parsed.value.duration;
    const reason = try ctx.allocator.dupe(u8, "manual ban");
    ctx.ban_mutex.lock();
    ctx.banned_peers.put(key, .{ .addr = addr, .expiry_time = expiry, .reason = reason }) catch {
        ctx.ban_mutex.unlock();
        ctx.allocator.free(addr);
        ctx.allocator.free(key);
        ctx.allocator.free(reason);
        res.status = 500;
        res.body = "{\"error\":\"failed to ban\"}";
        return;
    };
    ctx.ban_mutex.unlock();
    ctx.explorer.mutex.lock();
    var idx: usize = 0;
    for (ctx.explorer.known_nodes.items) |node| {
        idx += 1;
        const addr_fmt = node.format();
        const node_addr = std.mem.sliceTo(&addr_fmt, ' ');
        if (std.mem.eql(u8, node_addr, parsed.value.addr)) {
            if (ctx.explorer.connections.get(idx)) |conn| {
                std.posix.close(conn.socket);
                _ = ctx.explorer.connections.remove(idx);
            }
            break;
        }
    }
    ctx.explorer.mutex.unlock();
    res.body = "{\"success\":true}";
}

fn handleUnban(ctx: *DashboardState, req: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .JSON;
    const body = req.body() orelse {
        res.status = 400;
        res.body = "{\"error\":\"missing body\"}";
        return;
    };
    const parsed = std.json.parseFromSlice(struct { addr: []const u8 }, ctx.allocator, body, .{}) catch {
        res.status = 400;
        res.body = "{\"error\":\"invalid json\"}";
        return;
    };
    defer parsed.deinit();
    ctx.ban_mutex.lock();
    defer ctx.ban_mutex.unlock();
    if (ctx.banned_peers.fetchRemove(parsed.value.addr)) |kv| {
        ctx.allocator.free(kv.key);
        ctx.allocator.free(kv.value.addr);
        ctx.allocator.free(kv.value.reason);
        res.body = "{\"success\":true}";
    } else {
        res.status = 404;
        res.body = "{\"error\":\"peer not banned\"}";
    }
}

fn handleBannedList(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .JSON;
    var json = std.ArrayList(u8).empty;
    const writer = json.writer(ctx.allocator);
    try writer.writeAll("{\"banned\":[");
    ctx.ban_mutex.lock();
    defer ctx.ban_mutex.unlock();
    const now = std.time.timestamp();
    var first = true;
    var iter = ctx.banned_peers.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.expiry_time != 0 and entry.value_ptr.expiry_time <= now) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.print("{{\"addr\":\"{s}\",\"expiry\":{d},\"reason\":\"{s}\"}}", .{
            entry.value_ptr.addr,
            entry.value_ptr.expiry_time,
            entry.value_ptr.reason,
        });
    }
    try writer.writeAll("]}");
    res.body = try json.toOwnedSlice(ctx.allocator);
}

fn handleClearState(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .JSON;
    ctx.clearState();
    res.body = "{\"success\":true}";
}

fn stateSaver(state: *DashboardState) void {
    while (!state.explorer.should_stop.load(.acquire)) {
        std.Thread.sleep(60_000_000_000);
        if (state.explorer.should_stop.load(.acquire)) break;
        if (state.config.state_file) |path| {
            state.saveState(path);
        }
    }
}

fn updateBroadcaster(state: *DashboardState) void {
    while (!state.explorer.should_stop.load(.acquire)) {
        std.Thread.sleep(1_000_000_000);

        state.explorer.mutex.lock();
        const node_count = state.explorer.known_nodes.items.len;
        const mempool_count = state.explorer.mempool.count();
        state.explorer.mutex.unlock();

        const now = std.time.timestamp();
        const should_broadcast = node_count != state.last_node_count or
            mempool_count != state.last_mempool_count or
            now - state.last_broadcast_time >= 5;

        if (should_broadcast) {
            state.last_node_count = node_count;
            state.last_mempool_count = mempool_count;
            state.last_broadcast_time = now;

            if (buildStatusJson(state)) |json| {
                state.broadcastJson(json);
                state.allocator.free(json);
            } else |_| {}
        }
    }
}

fn buildStatusJson(state: *DashboardState) ![]u8 {
    const explorer = state.explorer;

    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    errdefer json.deinit(state.allocator);
    const writer = json.writer(state.allocator);

    try writer.writeAll("{\"api_version\":\"1.0\",");

    var connected: usize = 0;
    var connecting: usize = 0;
    var failed: usize = 0;

    var conn_iter = explorer.connections.valueIterator();
    while (conn_iter.next()) |conn| {
        switch (conn.*.state) {
            .connected => connected += 1,
            .connecting, .handshaking => connecting += 1,
            .failed => failed += 1,
        }
    }

    try writer.print("\"nodes\":{{\"total\":{d},\"connected\":{d},\"connecting\":{d},\"failed\":{d}}},", .{
        explorer.known_nodes.items.len,
        connected,
        connecting,
        failed,
    });

    var mempool_bytes: u64 = 0;
    var mempool_vbytes: u64 = 0;
    var size_iter = explorer.mempool.valueIterator();
    while (size_iter.next()) |entry| {
        if (entry.tx_data) |data| {
            mempool_bytes += data.len;
        }
        if (entry.vsize) |vs| {
            mempool_vbytes += vs;
        }
    }
    const mem_estimate = mempool_bytes + (explorer.mempool.count() * 200);
    try writer.print("\"mempool\":{{\"count\":{d},\"size_bytes\":{d},\"size_vbytes\":{d},\"memory\":{d}}},", .{
        explorer.mempool.count(), mempool_bytes, mempool_vbytes, mem_estimate,
    });

    var highest_peer: i32 = 0;
    var height_iter = explorer.node_metadata.valueIterator();
    while (height_iter.next()) |meta| {
        if (meta.start_height) |h| {
            if (h > highest_peer) highest_peer = h;
        }
    }
    const our_height: i32 = @intCast(explorer.blocks_seen);
    const synced = highest_peer > 0 and our_height > 0;
    const blocks_behind = if (highest_peer > our_height) highest_peer - our_height else 0;
    const progress: f32 = if (highest_peer > 0) @min(100.0, @as(f32, @floatFromInt(our_height)) / @as(f32, @floatFromInt(highest_peer)) * 100.0) else 0.0;
    try writer.print("\"sync_status\":{{\"synced\":{},\"height\":{d},\"highest_peer\":{d},\"blocks_behind\":{d},\"progress_pct\":{d:.1}}},", .{
        synced and blocks_behind == 0,
        our_height,
        highest_peer,
        blocks_behind,
        progress,
    });

    try writer.writeAll("\"block\":{");
    if (explorer.last_block_hash) |hash| {
        try writer.print("\"hash\":\"{s}\",\"time\":{d},\"seen\":{d}", .{
            hash,
            explorer.last_block_time.?,
            explorer.blocks_seen,
        });
    } else {
        try writer.writeAll("\"hash\":null,\"time\":null,\"seen\":0");
    }
    try writer.writeAll("},");

    var ua_counts = std.StringHashMap(usize).init(state.allocator);
    defer ua_counts.deinit();
    var meta_iter = explorer.node_metadata.iterator();
    while (meta_iter.next()) |entry| {
        if (entry.value_ptr.user_agent) |ua| {
            const gop = ua_counts.getOrPut(ua) catch continue;
            if (gop.found_existing) {
                gop.value_ptr.* += 1;
            } else {
                gop.value_ptr.* = 1;
            }
        }
    }
    try writer.writeAll("\"user_agents\":{");
    var ua_first = true;
    var ua_iter = ua_counts.iterator();
    while (ua_iter.next()) |entry| {
        if (!ua_first) try writer.writeByte(',');
        ua_first = false;
        try writer.writeByte('"');
        for (entry.key_ptr.*) |c| {
            if (c == '"' or c == '\\') try writer.writeByte('\\');
            try writer.writeByte(c);
        }
        try writer.print("\":{d}", .{entry.value_ptr.*});
    }
    try writer.writeAll("},");

    try writer.writeAll("\"node_list\":[");
    var first = true;
    var idx: usize = 0;
    for (explorer.known_nodes.items) |node| {
        idx += 1;
        if (explorer.connections.get(idx)) |conn| {
            if (!first) try writer.writeByte(',');
            first = false;

            const addr_fmt = node.format();
            const addr = std.mem.sliceTo(&addr_fmt, ' ');
            const metadata = explorer.node_metadata.get(idx);
            const state_str = switch (conn.state) {
                .connecting => "connecting",
                .handshaking => "handshaking",
                .connected => "connected",
                .failed => "failed",
            };

            try writer.print("{{\"index\":{d},\"addr\":\"{s}\",\"state\":\"{s}\"", .{
                idx,
                addr,
                state_str,
            });
            if (metadata) |m| {
                if (m.latency_ms) |lat| {
                    try writer.print(",\"latency\":{d}", .{lat});
                }
                try writer.print(",\"bytes_in\":{d},\"bytes_out\":{d},\"msgs_in\":{d},\"msgs_out\":{d}", .{
                    m.bytes_in,
                    m.bytes_out,
                    m.msgs_in,
                    m.msgs_out,
                });
                if (m.connect_time) |ct| {
                    try writer.print(",\"connect_time\":{d}", .{ct});
                }
                if (m.qualityScore()) |qs| {
                    try writer.print(",\"quality\":{d}", .{qs});
                }
                try writer.print(",\"reconnects\":{d}", .{m.reconnect_count});
                if (m.handshake_time_ms) |hs| {
                    try writer.print(",\"handshake_ms\":{d}", .{hs});
                }
            }
            try writer.writeAll("}");
        }
    }
    try writer.writeAll("],");

    var quality_sum: u32 = 0;
    var quality_count: u32 = 0;
    var quality_dist = [_]u32{ 0, 0, 0, 0 };
    var qual_iter = explorer.node_metadata.valueIterator();
    while (qual_iter.next()) |m| {
        if (m.qualityScore()) |qs| {
            quality_sum += qs;
            quality_count += 1;
            if (qs >= 80) quality_dist[0] += 1
            else if (qs >= 60) quality_dist[1] += 1
            else if (qs >= 40) quality_dist[2] += 1
            else quality_dist[3] += 1;
        }
    }
    const avg_quality: u32 = if (quality_count > 0) quality_sum / quality_count else 0;
    try writer.print("\"peer_quality\":{{\"avg\":{d},\"count\":{d},\"dist\":[{d},{d},{d},{d}]}},", .{
        avg_quality, quality_count, quality_dist[0], quality_dist[1], quality_dist[2], quality_dist[3],
    });

    var total_bytes_in: u64 = 0;
    var total_bytes_out: u64 = 0;
    var total_msgs_in: u64 = 0;
    var total_msgs_out: u64 = 0;
    var latency_sum: u64 = 0;
    var latency_count: u32 = 0;
    var stats_iter = explorer.node_metadata.valueIterator();
    while (stats_iter.next()) |m| {
        total_bytes_in += m.bytes_in;
        total_bytes_out += m.bytes_out;
        total_msgs_in += m.msgs_in;
        total_msgs_out += m.msgs_out;
        if (m.latency_ms) |lat| {
            latency_sum += lat;
            latency_count += 1;
        }
    }
    const avg_latency: u64 = if (latency_count > 0) latency_sum / latency_count else 0;
    const uptime = std.time.timestamp() - explorer.session_start;
    try writer.print("\"connection_stats\":{{\"bytes_in\":{d},\"bytes_out\":{d},\"msgs_in\":{d},\"msgs_out\":{d},\"avg_latency\":{d},\"uptime\":{d}}},", .{
        total_bytes_in, total_bytes_out, total_msgs_in, total_msgs_out, avg_latency, uptime,
    });

    try writer.writeAll("\"msg_types\":{");
    var msg_first = true;
    var msg_iter = explorer.msg_type_counts.iterator();
    while (msg_iter.next()) |entry| {
        if (!msg_first) try writer.writeByte(',');
        msg_first = false;
        try writer.print("\"{s}\":{d}", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    try writer.writeAll("},");

    var fee_rates: [500]f32 = undefined;
    var fee_count: usize = 0;
    var fee_buckets = [_]usize{ 0, 0, 0, 0, 0, 0 };
    var spam_count: usize = 0;
    var total_tx_count: usize = 0;

    try writer.writeAll("\"recent_txs\":[");
    first = true;
    var mp_iter = explorer.mempool.iterator();
    var tx_count: usize = 0;
    while (mp_iter.next()) |entry| {
        total_tx_count += 1;
        if (entry.value_ptr.spam_score >= 30) spam_count += 1;
        if (tx_count >= 50) continue;
        tx_count += 1;

        if (!first) try writer.writeByte(',');
        first = false;

        const mp_entry = entry.value_ptr;
        const announcements = mp_entry.announcements.items;
        try writer.print("{{\"txid\":\"{s}\",\"sources\":{d},\"first_seen\":{d},\"delays\":[", .{
            entry.key_ptr.*,
            announcements.len,
            mp_entry.first_seen,
        });
        for (announcements[1..], 0..) |ann, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print("{d}", .{ann.timestamp - mp_entry.first_seen});
        }
        try writer.writeAll("]");
        if (mp_entry.tx_data) |data| {
            try writer.print(",\"size\":{d},\"hex\":\"", .{data.len});
            for (data) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.writeByte('"');
        }
        if (mp_entry.vsize) |vsize| {
            try writer.print(",\"vsize\":{d}", .{vsize});
        }
        if (mp_entry.fee_rate) |rate| {
            try writer.print(",\"fee_rate\":{d:.1}", .{rate});
            if (fee_count < 500) {
                fee_rates[fee_count] = rate;
                fee_count += 1;
            }
            if (rate < 5) fee_buckets[0] += 1
            else if (rate < 10) fee_buckets[1] += 1
            else if (rate < 25) fee_buckets[2] += 1
            else if (rate < 50) fee_buckets[3] += 1
            else if (rate < 100) fee_buckets[4] += 1
            else fee_buckets[5] += 1;
        }
        if (mp_entry.version) |v| try writer.print(",\"version\":{d}", .{v});
        if (mp_entry.input_count) |c| try writer.print(",\"input_count\":{d}", .{c});
        if (mp_entry.output_count) |c| try writer.print(",\"output_count\":{d}", .{c});
        if (mp_entry.locktime) |lt| try writer.print(",\"locktime\":{d}", .{lt});
        try writer.print(",\"tx_type\":\"{s}\"", .{mp_entry.tx_type.toString()});
        try writer.print(",\"spam_score\":{d}", .{mp_entry.spam_score});
        const flags = mp_entry.spam_flags;
        try writer.print(",\"spam_flags\":{{\"dust\":{},\"op_return\":{},\"inscription\":{},\"low_fee\":{}}}", .{
            flags.has_dust, flags.has_op_return, flags.has_inscription, flags.low_fee,
        });
        if (mp_entry.witness_size > 0) {
            try writer.print(",\"witness_size\":{d}", .{mp_entry.witness_size});
        }
        try writer.writeByte('}');
    }
    try writer.writeAll("],");

    try writer.writeAll("\"fee_stats\":{");
    if (fee_count > 0) {
        std.mem.sort(f32, fee_rates[0..fee_count], {}, std.sort.asc(f32));
        const min_fee = fee_rates[0];
        const max_fee = fee_rates[fee_count - 1];
        const median_fee = fee_rates[fee_count / 2];
        var sum: f32 = 0;
        for (fee_rates[0..fee_count]) |r| sum += r;
        const avg_fee = sum / @as(f32, @floatFromInt(fee_count));
        try writer.print("\"min\":{d:.1},\"max\":{d:.1},\"median\":{d:.1},\"avg\":{d:.1},\"count\":{d}", .{
            min_fee, max_fee, median_fee, avg_fee, fee_count,
        });
    } else {
        try writer.writeAll("\"min\":null,\"max\":null,\"median\":null,\"avg\":null,\"count\":0");
    }
    try writer.print(",\"buckets\":[{d},{d},{d},{d},{d},{d}]", .{
        fee_buckets[0], fee_buckets[1], fee_buckets[2], fee_buckets[3], fee_buckets[4], fee_buckets[5],
    });
    try writer.writeAll("},");

    const spam_pct: f32 = if (total_tx_count > 0) @as(f32, @floatFromInt(spam_count)) / @as(f32, @floatFromInt(total_tx_count)) * 100.0 else 0.0;
    try writer.print("\"spam_stats\":{{\"spam_count\":{d},\"total_count\":{d},\"spam_pct\":{d:.1},\"regular_count\":{d}}},", .{
        spam_count, total_tx_count, spam_pct, total_tx_count - spam_count,
    });

    try writer.writeAll("\"topology\":{\"nodes\":[{\"id\":\"you\",\"type\":\"self\"}");
    var topo_idx: usize = 0;
    for (explorer.known_nodes.items) |node| {
        topo_idx += 1;
        if (explorer.connections.get(topo_idx)) |conn| {
            if (conn.state == .connected) {
                const addr_fmt = node.format();
                const addr = std.mem.sliceTo(&addr_fmt, ' ');
                const meta = explorer.node_metadata.get(topo_idx);
                try writer.print(",{{\"id\":\"{d}\",\"type\":\"peer\",\"addr\":\"{s}\"", .{ topo_idx, addr });
                if (meta) |m| {
                    if (m.latency_ms) |lat| try writer.print(",\"latency\":{d}", .{lat});
                    try writer.print(",\"msgs\":{d}", .{m.msgs_in + m.msgs_out});
                    if (m.qualityScore()) |qs| try writer.print(",\"quality\":{d}", .{qs});
                    if (m.user_agent) |ua| {
                        try writer.writeAll(",\"ua\":\"");
                        for (ua) |c| {
                            if (c == '"' or c == '\\') try writer.writeByte('\\');
                            try writer.writeByte(c);
                        }
                        try writer.writeByte('"');
                    }
                }
                try writer.writeByte('}');
            }
        }
    }
    try writer.writeAll("],\"edges\":[");
    first = true;
    topo_idx = 0;
    for (explorer.known_nodes.items) |_| {
        topo_idx += 1;
        if (explorer.connections.get(topo_idx)) |conn| {
            if (conn.state == .connected) {
                if (!first) try writer.writeByte(',');
                first = false;
                const meta = explorer.node_metadata.get(topo_idx);
                const weight: u64 = if (meta) |m| m.msgs_in + m.msgs_out else 0;
                try writer.print("{{\"source\":\"you\",\"target\":\"{d}\",\"weight\":{d}}}", .{ topo_idx, weight });
            }
        }
    }
    try writer.writeAll("],\"tx_sources\":[");
    first = true;
    var topo_mp_iter = explorer.mempool.iterator();
    var topo_tx_count: usize = 0;
    while (topo_mp_iter.next()) |entry| {
        if (topo_tx_count >= 20) break;
        topo_tx_count += 1;
        if (!first) try writer.writeByte(',');
        first = false;
        const announcements = entry.value_ptr.announcements.items;
        try writer.print("{{\"txid\":\"{s}\",\"peers\":[", .{entry.key_ptr.*});
        for (announcements, 0..) |ann, ai| {
            if (ai > 0) try writer.writeByte(',');
            try writer.print("{d}", .{ann.node_index});
        }
        try writer.writeAll("]}");
    }
    try writer.writeAll("]},");

    state.ban_mutex.lock();
    defer state.ban_mutex.unlock();
    const now = std.time.timestamp();
    var banned_count: usize = 0;
    try writer.writeAll("\"banned_peers\":[");
    var ban_first = true;
    var ban_iter = state.banned_peers.iterator();
    while (ban_iter.next()) |entry| {
        if (entry.value_ptr.expiry_time != 0 and entry.value_ptr.expiry_time <= now) continue;
        banned_count += 1;
        if (!ban_first) try writer.writeByte(',');
        ban_first = false;
        const remaining: i64 = if (entry.value_ptr.expiry_time == 0) -1 else entry.value_ptr.expiry_time - now;
        try writer.print("{{\"addr\":\"{s}\",\"expiry\":{d},\"remaining\":{d}}}", .{
            entry.value_ptr.addr,
            entry.value_ptr.expiry_time,
            remaining,
        });
    }
    try writer.print("],\"banned_count\":{d},", .{banned_count});

    try writer.print("\"timestamp\":{d}", .{std.time.timestamp()});
    try writer.writeAll("}");

    return json.toOwnedSlice(state.allocator);
}

const API_VERSION = "1.0";

fn setApiHeaders(res: *httpz.Response) void {
    res.content_type = .JSON;
    res.header("X-API-Version", API_VERSION);
    res.header("Access-Control-Allow-Origin", "*");
}

fn handleApiStatus(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    setApiHeaders(res);
    if (buildStatusJson(ctx)) |json| {
        res.body = json;
    } else |_| {
        res.status = 500;
        res.body = "{\"error\":\"internal error\"}";
    }
}

fn handleApiNodes(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    setApiHeaders(res);
    const explorer = ctx.explorer;

    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    const writer = json.writer(ctx.allocator);

    try writer.writeAll("{\"api_version\":\"1.0\",\"nodes\":[");
    var first = true;
    var idx: usize = 0;
    for (explorer.known_nodes.items) |node| {
        idx += 1;
        if (explorer.connections.get(idx)) |conn| {
            if (!first) try writer.writeByte(',');
            first = false;
            const addr_fmt = node.format();
            const addr = std.mem.sliceTo(&addr_fmt, ' ');
            const metadata = explorer.node_metadata.get(idx);
            const state_str = switch (conn.state) {
                .connecting => "connecting",
                .handshaking => "handshaking",
                .connected => "connected",
                .failed => "failed",
            };
            try writer.print("{{\"index\":{d},\"addr\":\"{s}\",\"state\":\"{s}\"", .{ idx, addr, state_str });
            if (metadata) |m| {
                if (m.latency_ms) |lat| try writer.print(",\"latency\":{d}", .{lat});
                try writer.print(",\"bytes_in\":{d},\"bytes_out\":{d},\"msgs_in\":{d},\"msgs_out\":{d}", .{ m.bytes_in, m.bytes_out, m.msgs_in, m.msgs_out });
                if (m.connect_time) |ct| try writer.print(",\"connect_time\":{d}", .{ct});
                if (m.qualityScore()) |qs| try writer.print(",\"quality\":{d}", .{qs});
                if (m.user_agent) |ua| {
                    try writer.writeAll(",\"user_agent\":\"");
                    for (ua) |c| {
                        if (c == '"' or c == '\\') try writer.writeByte('\\');
                        try writer.writeByte(c);
                    }
                    try writer.writeByte('"');
                }
            }
            try writer.writeAll("}");
        }
    }
    try writer.print("],\"total\":{d},\"timestamp\":{d}}}", .{ idx, std.time.timestamp() });
    res.body = try json.toOwnedSlice(ctx.allocator);
}

fn handleApiMempool(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    setApiHeaders(res);
    const explorer = ctx.explorer;

    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    const writer = json.writer(ctx.allocator);

    var mempool_bytes: u64 = 0;
    var mempool_vbytes: u64 = 0;
    var size_iter = explorer.mempool.valueIterator();
    while (size_iter.next()) |entry| {
        if (entry.tx_data) |data| mempool_bytes += data.len;
        if (entry.vsize) |vs| mempool_vbytes += vs;
    }

    try writer.print("{{\"api_version\":\"1.0\",\"count\":{d},\"bytes\":{d},\"vbytes\":{d},\"transactions\":[", .{
        explorer.mempool.count(),
        mempool_bytes,
        mempool_vbytes,
    });

    var first = true;
    var mp_iter = explorer.mempool.iterator();
    var tx_count: usize = 0;
    while (mp_iter.next()) |entry| {
        if (tx_count >= 100) break;
        tx_count += 1;
        if (!first) try writer.writeByte(',');
        first = false;
        const mp_entry = entry.value_ptr;
        try writer.print("{{\"txid\":\"{s}\",\"sources\":{d},\"first_seen\":{d}", .{
            entry.key_ptr.*,
            mp_entry.announcements.items.len,
            mp_entry.first_seen,
        });
        if (mp_entry.fee_rate) |fr| try writer.print(",\"fee_rate\":{d:.2}", .{fr});
        if (mp_entry.vsize) |vs| try writer.print(",\"vsize\":{d}", .{vs});
        try writer.print(",\"spam_score\":{d}}}", .{mp_entry.spam_score});
    }
    try writer.print("],\"timestamp\":{d}}}", .{std.time.timestamp()});
    res.body = try json.toOwnedSlice(ctx.allocator);
}

fn handleApiBlocks(ctx: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    setApiHeaders(res);
    const explorer = ctx.explorer;

    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    const writer = json.writer(ctx.allocator);

    try writer.writeAll("{\"api_version\":\"1.0\",\"latest\":{");
    if (explorer.last_block_hash) |hash| {
        try writer.print("\"hash\":\"{s}\",\"time\":{d},\"seen\":{d}", .{
            hash,
            explorer.last_block_time.?,
            explorer.blocks_seen,
        });
    } else {
        try writer.writeAll("\"hash\":null,\"time\":null,\"seen\":0");
    }
    try writer.print("}},\"blocks_seen\":{d},\"timestamp\":{d}}}", .{
        explorer.blocks_seen,
        std.time.timestamp(),
    });
    res.body = try json.toOwnedSlice(ctx.allocator);
}
