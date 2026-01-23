const std = @import("std");

const state_mod = @import("state.zig");

const DashboardState = state_mod.DashboardState;

pub fn buildStatusJson(state: *DashboardState) ![]u8 {
    const explorer = state.explorer;

    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    errdefer json.deinit(state.allocator);
    const writer = json.writer(state.allocator);

    try writer.writeAll("{\"api_version\":\"1.0\",");

    try writeConnectionCounts(explorer, writer);
    try writeMempoolStats(explorer, writer);
    try writeSyncStatus(explorer, writer);
    try writeBlockInfo(explorer, writer);
    try writeUserAgents(state, writer);
    try writeNodeList(state, writer);
    try writeLatencyStats(state, writer);
    try writeConnectionStats(state, writer);
    try writeMsgTypes(explorer, writer);
    try writeFeeStats(state, writer);
    try writeSpamStats(state, writer);
    try writePeerQuality(state, writer);
    try writeTxData(state, writer);
    try writeTopology(state, writer);
    try writeBannedPeers(state, writer);

    try writer.print("\"timestamp\":{d}", .{std.time.timestamp()});
    try writer.writeAll("}");

    return json.toOwnedSlice(state.allocator);
}

fn writeConnectionCounts(explorer: anytype, writer: anytype) !void {
    var connected: usize = 0;
    var connecting: usize = 0;
    var failed: usize = 0;

    var iter = explorer.connections.valueIterator();
    while (iter.next()) |conn| {
        switch (conn.*.state) {
            .connected => connected += 1,
            .connecting, .handshaking => connecting += 1,
            .failed => failed += 1,
        }
    }

    try writer.print("\"nodes\":{{\"total\":{d},\"connected\":{d},\"connecting\":{d},\"failed\":{d}}},", .{
        explorer.known_nodes.items.len, connected, connecting, failed,
    });
}

fn writeMempoolStats(explorer: anytype, writer: anytype) !void {
    var mempool_bytes: u64 = 0;

    var iter = explorer.mempool.valueIterator();
    while (iter.next()) |entry| {
        if (entry.tx_data) |data| mempool_bytes += data.len;
    }

    const mem_estimate = mempool_bytes + (explorer.mempool.count() * 200);
    try writer.print("\"mempool\":{{\"count\":{d},\"size_bytes\":{d},\"size_vbytes\":{d},\"vbytes\":{d},\"memory\":{d},\"memory_estimate\":{d}}},", .{
        explorer.mempool.count(), mempool_bytes, mempool_bytes, mempool_bytes, mem_estimate, mem_estimate,
    });
}

fn writeUserAgents(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;

    var ua_counts = std.StringHashMap(usize).init(state.allocator);
    defer ua_counts.deinit();

    var iter = explorer.node_metadata.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.user_agent) |ua| {
            const gop = ua_counts.getOrPut(ua) catch continue;
            gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + 1 else 1;
        }
    }

    try writer.writeAll("\"user_agents\":{");
    var first = true;
    var ua_iter = ua_counts.iterator();
    while (ua_iter.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writeEscapedString(writer, entry.key_ptr.*);
        try writer.print(":{d}", .{entry.value_ptr.*});
    }
    try writer.writeAll("},");
}

pub fn writeEscapedString(writer: anytype, str: []const u8) !void {
    try writer.writeByte('"');
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try writer.print("\\u{x:0>4}", .{c}),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

fn writeNodeList(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;
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

            try writer.print("{{\"index\":{d},\"addr\":\"{s}\",\"state\":\"{s}\"", .{ idx, addr, state_str });
            if (metadata) |m| {
                if (m.latency_ms) |lat| try writer.print(",\"latency\":{d}", .{lat});
                if (m.user_agent) |ua| {
                    try writer.writeAll(",\"user_agent\":");
                    try writeEscapedString(writer, ua);
                }
            }
            try writer.writeAll("}");
        }
    }
    try writer.writeAll("],");
}

fn writeLatencyStats(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;
    var latency_sum: u64 = 0;
    var latency_count: u32 = 0;

    var iter = explorer.node_metadata.valueIterator();
    while (iter.next()) |m| {
        if (m.latency_ms) |lat| {
            latency_sum += lat;
            latency_count += 1;
        }
    }

    const avg_latency: u64 = if (latency_count > 0) latency_sum / latency_count else 0;
    try writer.print("\"latency_stats\":{{\"avg\":{d},\"count\":{d}}},", .{ avg_latency, latency_count });
}

fn writeSyncStatus(explorer: anytype, writer: anytype) !void {
    const highest = explorer.highest_peer_height;
    const synced = highest > 0;
    try writer.print("\"sync_status\":{{\"synced\":{},\"height\":{d},\"highest_peer\":{d},\"blocks_behind\":0,\"progress_pct\":{d}}},", .{
        synced, highest, highest, if (synced) @as(u32, 100) else @as(u32, 0),
    });
}

fn writeBlockInfo(explorer: anytype, writer: anytype) !void {
    try writer.writeAll("\"block\":{");
    if (explorer.last_block_hash) |hash| {
        try writer.print("\"hash\":\"{s}\",", .{hash});
    } else {
        try writer.writeAll("\"hash\":null,");
    }
    if (explorer.last_block_time) |time| {
        try writer.print("\"time\":{d},", .{time});
    } else {
        try writer.writeAll("\"time\":null,");
    }
    try writer.print("\"seen\":{d}}},", .{explorer.blocks_seen});
}

fn writeConnectionStats(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;
    var latency_sum: u64 = 0;
    var latency_count: u32 = 0;
    var total_bytes_in: u64 = 0;
    var total_bytes_out: u64 = 0;
    var total_msgs_in: u64 = 0;
    var total_msgs_out: u64 = 0;

    var iter = explorer.node_metadata.valueIterator();
    while (iter.next()) |m| {
        if (m.latency_ms) |lat| {
            latency_sum += lat;
            latency_count += 1;
        }
        total_bytes_in += m.bytes_in;
        total_bytes_out += m.bytes_out;
        total_msgs_in += m.msgs_in;
        total_msgs_out += m.msgs_out;
    }

    const avg_latency: u64 = if (latency_count > 0) latency_sum / latency_count else 0;
    const now = std.time.timestamp();
    const uptime: i64 = now - explorer.session_start;
    try writer.print("\"connection_stats\":{{\"bytes_in\":{d},\"bytes_out\":{d},\"msgs_in\":{d},\"msgs_out\":{d},\"avg_latency\":{d},\"uptime\":{d}}},", .{
        total_bytes_in, total_bytes_out, total_msgs_in, total_msgs_out, avg_latency, uptime,
    });
}

fn writeMsgTypes(explorer: anytype, writer: anytype) !void {
    try writer.writeAll("\"msg_types\":{");
    var first = true;
    var iter = explorer.msg_type_counts.iterator();
    while (iter.next()) |entry| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.print("\"{s}\":{d}", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    try writer.writeAll("},");
}

fn writeFeeStats(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;
    var min_fee: u64 = std.math.maxInt(u64);
    var max_fee: u64 = 0;
    var sum_fee: u64 = 0;
    var count: u32 = 0;

    var iter = explorer.node_metadata.valueIterator();
    while (iter.next()) |m| {
        if (m.fee_filter > 0) {
            if (m.fee_filter < min_fee) min_fee = m.fee_filter;
            if (m.fee_filter > max_fee) max_fee = m.fee_filter;
            sum_fee += m.fee_filter;
            count += 1;
        }
    }

    const avg: u64 = if (count > 0) sum_fee / count else 0;
    const median = avg;
    const min_out: u64 = if (count > 0) min_fee / 1000 else 0;
    const max_out: u64 = max_fee / 1000;
    const avg_out: u64 = avg / 1000;

    try writer.print("\"fee_stats\":{{\"min\":{d},\"max\":{d},\"median\":{d},\"avg\":{d},\"count\":{d},\"buckets\":[0,0,0,0,0,0]}},", .{
        min_out, max_out, median / 1000, avg_out, count,
    });
}

fn writeSpamStats(state: *DashboardState, writer: anytype) !void {
    const total = state.explorer.mempool.count();
    try writer.print("\"spam_stats\":{{\"spam_count\":0,\"total_count\":{d},\"spam_pct\":0,\"regular_count\":{d}}},", .{ total, total });
}

fn writePeerQuality(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;
    var quality_sum: u64 = 0;
    var quality_count: u32 = 0;

    var iter = explorer.node_metadata.valueIterator();
    while (iter.next()) |m| {
        if (m.ever_connected) {
            var score: u32 = 50;
            if (m.latency_ms) |lat| {
                if (lat < 100) score += 30 else if (lat < 500) score += 15;
            }
            if (m.msgs_in > 10) score += 20;
            quality_sum += score;
            quality_count += 1;
        }
    }

    const avg: u64 = if (quality_count > 0) quality_sum / quality_count else 0;
    try writer.print("\"peer_quality\":{{\"avg\":{d},\"count\":{d},\"dist\":[0,0,0,0]}},", .{ avg, quality_count });
}

fn writeTxData(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;

    try writer.writeAll("\"recent_txs\":[");
    var first = true;
    var mp_iter = explorer.mempool.iterator();
    var tx_count: usize = 0;
    while (mp_iter.next()) |entry| {
        if (tx_count >= 50) break;
        tx_count += 1;

        if (!first) try writer.writeByte(',');
        first = false;

        const mp_entry = entry.value_ptr;
        const announcements = mp_entry.announcements.items;
        try writer.print("{{\"txid\":\"{s}\",\"sources\":{d},\"first_seen\":{d}", .{
            entry.key_ptr.*, announcements.len, mp_entry.first_seen,
        });
        if (mp_entry.tx_data) |data| {
            try writer.print(",\"size\":{d}", .{data.len});
        }
        try writer.writeByte('}');
    }
    try writer.writeAll("],");
}

fn writeTopology(state: *DashboardState, writer: anytype) !void {
    const explorer = state.explorer;
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
                    if (m.user_agent) |ua| {
                        try writer.writeAll(",\"ua\":");
                        try writeEscapedString(writer, ua);
                    }
                }
                try writer.writeByte('}');
            }
        }
    }
    try writer.writeAll("],\"edges\":[");
    var first = true;
    topo_idx = 0;
    for (explorer.known_nodes.items) |_| {
        topo_idx += 1;
        if (explorer.connections.get(topo_idx)) |conn| {
            if (conn.state == .connected) {
                if (!first) try writer.writeByte(',');
                first = false;
                try writer.print("{{\"source\":\"you\",\"target\":\"{d}\"}}", .{topo_idx});
            }
        }
    }
    try writer.writeAll("]},");
}

fn writeBannedPeers(state: *DashboardState, writer: anytype) !void {
    state.ban_mutex.lock();
    defer state.ban_mutex.unlock();
    const now = std.time.timestamp();
    var banned_count: usize = 0;
    try writer.writeAll("\"banned_peers\":[");
    var first = true;
    var iter = state.banned_peers.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.expiry_time != 0 and entry.value_ptr.expiry_time <= now) continue;
        banned_count += 1;
        if (!first) try writer.writeByte(',');
        first = false;
        const remaining: i64 = if (entry.value_ptr.expiry_time == 0) -1 else entry.value_ptr.expiry_time - now;
        try writer.print("{{\"addr\":\"{s}\",\"expiry\":{d},\"remaining\":{d}}}", .{
            entry.value_ptr.addr, entry.value_ptr.expiry_time, remaining,
        });
    }
    try writer.print("],\"banned_count\":{d},", .{banned_count});
}
