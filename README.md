# Yam

Lightweight, zero-dependency Bitcoin P2P CLI network tool. Connect to nodes, observe mempool propagation, export data, and broadcast transactions (experimental).

[Yam](https://en.wikipedia.org/wiki/Yam_(route)) is named after the Mongolian messaging system.

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/27722733-213d-4832-89c0-c1e19c71a9db" />


## Build

```
zig build
```

Requires Zig 0.15.2+

WARNING: It has mostly been tested on MacOS. Windows has basic support. Linux support will hopefully come down the road.

## Usage

### Explorer Mode

```
./zig-out/bin/yam
```

Commands:
```
discover, d            Discover nodes via DNS seeds
nodes, n, ls           List nodes (with connection status)
connect, c [n|n-m|ip]  Connect to nodes (all if no args)
disconnect, dc <n>     Disconnect from node(s)
stream <n> on|off      Toggle message streaming
getaddr, ga [n...]     Request addresses (all if no args)
ping [n...]            Measure latency (all if no args)
graph                  Show peer advertisement graph
mempool, mp            Show observed mempool transactions
status, s              Show connection status
export, x <nodes|mempool|graph|tx> [csv|dot|txid]  Export data
help, h, ?             Show this help
quit, q                Exit
```

Examples:
```
> d                     # discover nodes via DNS
Found 54 nodes (54 new)

> c                     # connect to all
Connecting to 54 node(s)...

> c 1-10                # connect to range
> c 5 12 20             # connect to specific nodes
> c 192.168.1.1:8333    # connect by IP

> n                     # list nodes
  [  1] 172.7.56.107:8333    connected    45ms /Satoshi:27.0.0/
  [  2] 162.220.94.10:8333   connecting
  [  3] 49.13.4.145:8333     failed

> ping                  # measure latency to all connected
> ping 1-5              # ping specific nodes

> ga                    # request addresses from all connected

> s                     # status
Status:
  Nodes:       42 connected / 156 known
  Connections: 12 connecting, 5 failed, 97 other
  Mempool:     234 with data / 412 seen

> mp                    # show mempool
  abc123... (225 bytes)
    Announced by 3 node(s): [1] [4] [12]

> export nodes          # export to nodes_2025-01-04_143052.csv
> export mempool        # export to mempool_2025-01-04_143052.csv
> export graph          # export to graph_2025-01-04_143052.csv
> export graph dot      # export to graph_2025-01-04_143052.dot (graphviz)
> export tx abc123...   # export to abc123...hex

> stream 1 on           # watch raw messages from node 1
> dc 1                  # disconnect node 1
> q                     # quit
```

### Broadcast Mode (still WIP)

```
./zig-out/bin/yam broadcast <tx_hex> [options]
```

Options:
- `--peers, -p <n>` - number of peers (default: 8)
- `--simultaneous, -s` - send to all peers at once (default: staggered)
- `--discover, -d` - expand peer list via getaddr

Examples:
```
# broadcast to 8 random peers with staggered timing (default)
./zig-out/bin/yam broadcast 0100000001...

# broadcast to 10 peers simultaneously
./zig-out/bin/yam broadcast 0100000001... --peers 10 --simultaneous

# use recursive peer discovery first
./zig-out/bin/yam broadcast 0100000001... --discover
```

### Signet

Set `YAM_SIGNET` environment variable to use signet instead of mainnet:

```
# Default public signet
YAM_SIGNET=1 ./zig-out/bin/yam

# Custom signet (provide challenge hex)
YAM_SIGNET=<challenge_hex> ./zig-out/bin/yam

# Works with any command
YAM_SIGNET=1 ./zig-out/bin/yam broadcast 0100000001...
```

## Export Formats

**nodes.csv**
```
ip,port,user_agent,connection_established,latency_ms
172.7.56.107,8333,/Satoshi:27.0.0/,true,45
162.220.94.10,8333,,false,
```

**mempool.csv**
```
txid,node_ip,node_user_agent,announcement_timestamp
abc123...,172.7.56.107:8333,/Satoshi:27.0.0/,1704384000
abc123...,162.220.94.10:8333,/Satoshi:28.0.0/,1704384001
```

Each row is one announcement. Same txid appears multiple times if announced by multiple nodes.

**graph.csv**
```
source,target
172.7.56.107:8333,10.0.0.1:8333
172.7.56.107:8333,10.0.0.2:8333
```

## Graph

The `graph` command shows which peers were advertised by which nodes via `getaddr` responses. An edge `A <- B` means node B included node A in its address response.

This does **not** show actual connections between nodes. Bitcoin nodes return a random subset of their address database when responding to `getaddr`, not their current connections. The graph is more of a curiosity for exploring network topology than a reliable map of the network.
