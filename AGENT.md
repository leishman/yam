AGENT.md - Project Yam
1. Project Overview
Name: Yam (Named after the Mongol Empire's high-speed courier system).

Mission: A high-performance, low-dependency Bitcoin P2P networking utility.

Scope: - Phase 1: Mempool visualization (Passive/Active listening).

Phase 2: Anonymous transaction broadcasting (SOCKS5/Tor support).

Constraints: NO cryptography or private key management. The tool handles pre-signed raw hex transactions only.

2. Tech Stack & Versioning
Language: Zig 0.15.2 (Bleeding Edge).

Standard Library: Only use std. Avoid third-party dependencies unless explicitly requested.

Build System: Use the std.Build API (Zig 0.15.2 style).

Target: Linux/macOS/Windows (Cross-platform capability).

3. Critical AI Instructions (Anti-Hallucination)
Zig Versioning: Do NOT use std.build.Builder (deprecated). Use *std.Build.

Memory: Always prefer std.heap.GeneralPurposeAllocator for development and std.heap.FixedBufferAllocator for high-frequency packet parsing.

Endianness: Bitcoin is Little-Endian. Always use std.mem.readInt(u32, bytes, .little) and std.mem.writeInt(u32, bytes, .little).

Error Handling: Use Zig's try, catch, and errdefer patterns. No panic in networking code; handle socket timeouts and malformed packets gracefully.

4. Bitcoin Protocol Context
Mainnet Magic: 0xD9B4BEF9

Network Port: 8333

Message Header (24 bytes):

[4]u8 Magic

[12]u8 Command (null-padded)

u32 Payload Length

u32 Checksum (First 4 bytes of Double-SHA256 of payload).

Handshake Flow: version -> verack -> (Connection Established).

5. Coding Style & Idioms
Naming: Follow Zig's standard (CamelCase for types, snake_case for functions/variables).

Theming: Internal modules should use military-history metaphors where appropriate (e.g., src/courier.zig for P2P logic, src/scout.zig for mempool parsing).

Memory Safety: Be explicit about memory ownership. If a function allocates, it must take an Allocator as a parameter.

6. Current Task Focus
Active Goal: Establishing the initial version message handshake with a Bitcoin node.

Next Step: Implementing a SOCKS5 proxy wrapper for anonymous connection.