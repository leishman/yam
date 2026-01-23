const std = @import("std");
const net = std.net;

const http = @import("http.zig");
const state_mod = @import("state.zig");
const json_mod = @import("json.zig");

const DashboardState = state_mod.DashboardState;

const writeEscapedJsonString = json_mod.writeEscapedString;

pub fn handleStatus(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream) !void {
    const json = json_mod.buildStatusJson(state) catch
        return http.sendJson(stream, 500, "{\"error\":\"internal error\"}");
    defer allocator.free(json);
    try http.sendJson(stream, 200, json);
}

pub fn handleNodes(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream) !void {
    const explorer = state.explorer;
    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    const writer = json.writer(allocator);

    try writer.writeAll("{\"api_version\":\"1.0\",\"nodes\":[");
    var first = true;
    var idx: usize = 0;
    for (explorer.known_nodes.items) |node| {
        idx += 1;
        if (explorer.connections.get(idx)) |c| {
            if (!first) try writer.writeByte(',');
            first = false;
            const addr_fmt = node.format();
            const addr = std.mem.sliceTo(&addr_fmt, ' ');
            const metadata = explorer.node_metadata.get(idx);
            const state_str = switch (c.state) {
                .connecting => "connecting",
                .handshaking => "handshaking",
                .connected => "connected",
                .failed => "failed",
            };
            try writer.print("{{\"index\":{d},\"addr\":\"{s}\",\"state\":\"{s}\"", .{ idx, addr, state_str });
            if (metadata) |m| {
                if (m.latency_ms) |lat| try writer.print(",\"latency\":{d}", .{lat});
                if (m.user_agent) |ua| {
                    try writer.writeAll(",\"user_agent\":");
                    try writeEscapedJsonString(writer, ua);
                }
            }
            try writer.writeAll("}");
        }
    }
    try writer.print("],\"total\":{d},\"timestamp\":{d}}}", .{ idx, std.time.timestamp() });
    const body = try json.toOwnedSlice(allocator);
    defer allocator.free(body);
    try http.sendJson(stream, 200, body);
}

pub fn handleMempool(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream) !void {
    const explorer = state.explorer;
    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    const writer = json.writer(allocator);

    var mempool_bytes: u64 = 0;
    var size_iter = explorer.mempool.valueIterator();
    while (size_iter.next()) |entry| {
        if (entry.tx_data) |data| mempool_bytes += data.len;
    }

    try writer.print("{{\"api_version\":\"1.0\",\"count\":{d},\"bytes\":{d},\"transactions\":[", .{
        explorer.mempool.count(), mempool_bytes,
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
            entry.key_ptr.*, mp_entry.announcements.items.len, mp_entry.first_seen,
        });
        if (mp_entry.tx_data) |data| try writer.print(",\"size\":{d}", .{data.len});
        try writer.writeByte('}');
    }
    try writer.print("],\"timestamp\":{d}}}", .{std.time.timestamp()});
    const body = try json.toOwnedSlice(allocator);
    defer allocator.free(body);
    try http.sendJson(stream, 200, body);
}

pub fn handleBlocks(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream) !void {
    _ = allocator;
    _ = state;
    try http.sendJson(stream, 200, "{\"api_version\":\"1.0\",\"blocks\":[]}");
}

pub fn handleBannedList(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream) !void {
    var json = std.ArrayList(u8).empty;
    const writer = json.writer(allocator);
    try writer.writeAll("{\"banned\":[");
    state.ban_mutex.lock();
    defer state.ban_mutex.unlock();
    const now = std.time.timestamp();
    var first = true;
    var iter = state.banned_peers.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.expiry_time != 0 and entry.value_ptr.expiry_time <= now) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("{\"addr\":");
        try writeEscapedJsonString(writer, entry.value_ptr.addr);
        try writer.print(",\"expiry\":{d},\"reason\":", .{entry.value_ptr.expiry_time});
        try writeEscapedJsonString(writer, entry.value_ptr.reason);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
    const body = try json.toOwnedSlice(allocator);
    defer allocator.free(body);
    try http.sendJson(stream, 200, body);
}

pub fn handleDisconnect(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream, body: []const u8) !void {
    const DisconnectRequest = struct { index: usize };
    const parsed = std.json.parseFromSlice(DisconnectRequest, allocator, body, .{}) catch
        return http.sendJson(stream, 400, "{\"error\":\"invalid json\"}");
    defer parsed.deinit();

    state.explorer.mutex.lock();
    defer state.explorer.mutex.unlock();

    const conn = state.explorer.connections.get(parsed.value.index) orelse
        return http.sendJson(stream, 404, "{\"error\":\"peer not found\"}");

    std.posix.close(conn.socket);
    _ = state.explorer.connections.remove(parsed.value.index);
    try http.sendJson(stream, 200, "{\"success\":true}");
}

pub fn handleBan(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream, body: []const u8) !void {
    const BanRequest = struct { addr: []const u8, duration: i64 };
    const parsed = std.json.parseFromSlice(BanRequest, allocator, body, .{}) catch
        return http.sendJson(stream, 400, "{\"error\":\"invalid json\"}");
    defer parsed.deinit();

    const ban_addr = parsed.value.addr;
    const expiry: i64 = if (parsed.value.duration == 0) 0 else std.time.timestamp() + parsed.value.duration;

    {
        state.ban_mutex.lock();
        defer state.ban_mutex.unlock();

        if (state.banned_peers.getPtr(ban_addr)) |existing| {
            existing.expiry_time = expiry;
        } else {
            const addr = allocator.dupe(u8, ban_addr) catch
                return http.sendJson(stream, 500, "{\"error\":\"failed to ban\"}");
            errdefer allocator.free(addr);
            const key = allocator.dupe(u8, ban_addr) catch
                return http.sendJson(stream, 500, "{\"error\":\"failed to ban\"}");
            errdefer allocator.free(key);
            const reason = allocator.dupe(u8, "manual ban") catch
                return http.sendJson(stream, 500, "{\"error\":\"failed to ban\"}");
            state.banned_peers.put(key, .{ .addr = addr, .expiry_time = expiry, .reason = reason }) catch {
                allocator.free(reason);
                return http.sendJson(stream, 500, "{\"error\":\"failed to ban\"}");
            };
        }
    }

    disconnectPeerByAddr(state, ban_addr);
    try http.sendJson(stream, 200, "{\"success\":true}");
}

fn disconnectPeerByAddr(state: *DashboardState, target_addr: []const u8) void {
    state.explorer.mutex.lock();
    defer state.explorer.mutex.unlock();

    var idx: usize = 0;
    for (state.explorer.known_nodes.items) |node| {
        idx += 1;
        const addr_fmt = node.format();
        const node_addr = std.mem.sliceTo(&addr_fmt, ' ');
        if (std.mem.eql(u8, node_addr, target_addr)) {
            if (state.explorer.connections.get(idx)) |c| {
                std.posix.close(c.socket);
                _ = state.explorer.connections.remove(idx);
            }
            return;
        }
    }
}

pub fn handleUnban(allocator: std.mem.Allocator, state: *DashboardState, stream: net.Stream, body: []const u8) !void {
    const UnbanRequest = struct { addr: []const u8 };
    const parsed = std.json.parseFromSlice(UnbanRequest, allocator, body, .{}) catch
        return http.sendJson(stream, 400, "{\"error\":\"invalid json\"}");
    defer parsed.deinit();

    state.ban_mutex.lock();
    defer state.ban_mutex.unlock();

    const kv = state.banned_peers.fetchRemove(parsed.value.addr) orelse
        return http.sendJson(stream, 404, "{\"error\":\"peer not banned\"}");

    allocator.free(kv.key);
    allocator.free(kv.value.addr);
    allocator.free(kv.value.reason);
    try http.sendJson(stream, 200, "{\"success\":true}");
}

pub fn handleClearState(state: *DashboardState, stream: net.Stream) !void {
    state.clearState();
    try http.sendJson(stream, 200, "{\"success\":true}");
}
