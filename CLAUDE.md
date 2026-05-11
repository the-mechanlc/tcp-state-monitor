# tcp-state-monitor

A Rust + Aya eBPF tool that monitors TCP state transitions on Linux and prints them to stdout with optional filters.

## Architecture

Cargo workspace with 3 crates:

```
tcp-state-monitor/
├── Cargo.toml                  # workspace root
├── tcp-state-monitor/          # userspace binary (std)
│   ├── Cargo.toml
│   └── src/main.rs
├── tcp-state-monitor-ebpf/     # eBPF program (no_std, bpf target)
│   ├── Cargo.toml
│   └── src/main.rs
└── tcp-state-monitor-common/   # shared structs (no_std compatible)
    ├── Cargo.toml
    └── src/lib.rs
```

## eBPF Program

**Hook:** `tracepoint/sock/inet_sock_set_state`

This tracepoint fires on every TCP state transition. The eBPF program:
1. Reads the tracepoint context fields: `skaddr`, `oldstate`, `newstate`, `sport`, `dport`, `saddr`, `daddr`, `protocol`
2. Filters: only process events where `protocol == IPPROTO_TCP` (6)
3. Reads process info: `bpf_get_current_pid_tgid()` → PID, `bpf_get_current_comm()` → comm (16 bytes)
4. Fills a `TcpEvent` struct and writes it to a RingBuf map

The tracepoint context struct for `inet_sock_set_state` (from kernel BTF):
```c
struct trace_event_raw_inet_sock_set_state {
    __u64 unused;        // common fields
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};
```

In Rust Aya eBPF, access via `TracePointContext` and `ctx.read_at::<T>(offset)` OR use the Aya `#[tracepoint]` macro and define a matching Rust struct.

## Shared Structs (tcp-state-monitor-common)

```rust
// Must be #[repr(C)] and no_std compatible
#[repr(C)]
pub struct TcpEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub src_addr: u32,   // IPv4, network byte order
    pub dst_addr: u32,   // IPv4, network byte order
    pub src_port: u16,   // host byte order
    pub dst_port: u16,   // host byte order
    pub old_state: u32,
    pub new_state: u32,
}

// TCP state names for display
pub fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}
```

## Userspace Binary (tcp-state-monitor)

### CLI flags (use `clap` with derive)

```
--addr <IP>     Filter by src OR dst IPv4 address (e.g. 192.168.1.5)
--port <PORT>   Filter by src OR dst port
--state <NAME>  Only show transitions INTO this state (e.g. ESTABLISHED, TIME_WAIT)
--pid <PID>     Filter by PID
```

All filters are AND-ed together. No filter = show everything.

### Output format (one line per event)

```
[PID 1234 / curl    ] 192.168.1.5:54321 -> 1.2.3.4:443    SYN_SENT -> ESTABLISHED
```

- PID and comm are left-justified in fixed-width fields
- Addresses printed as dotted-decimal via `std::net::Ipv4Addr::from(u32)`
- State names from `tcp_state_name()`
- comm is null-terminated C string in the [u8; 16] array — trim at first null byte

### Main loop

1. Load the eBPF object (compiled via `aya-build` / `include_bytes_aligned!`)
2. Attach the tracepoint program
3. Open the RingBuf map
4. In a `tokio` async loop, poll the ring buffer with `RingBuf::next()`
5. Parse each event as `TcpEvent`, apply CLI filters, print or skip

Use `tokio` as the async runtime.

## Dependencies

### tcp-state-monitor/Cargo.toml
```toml
[dependencies]
aya = { version = "0.13", features = ["async_tokio"] }
aya-log = "0.2"
tcp-state-monitor-common = { path = "../tcp-state-monitor-common" }
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
log = "0.4"
env_logger = "0.11"

[build-dependencies]
aya-build = "0.1"
```

### tcp-state-monitor-ebpf/Cargo.toml
```toml
[dependencies]
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"
tcp-state-monitor-common = { path = "../tcp-state-monitor-common" }
```

### tcp-state-monitor-common/Cargo.toml
```toml
[lib]
[dependencies]
# no_std compatible, no external deps needed
```

## Build System

Use `aya-build` in the userspace crate's `build.rs` to compile the eBPF program:

```rust
// tcp-state-monitor/build.rs
use aya_build::cargo_metadata;
fn main() {
    let packages = cargo_metadata();
    aya_build::build_ebpf(
        packages.iter().find(|p| p.name == "tcp-state-monitor-ebpf").unwrap(),
    ).unwrap();
}
```

The compiled eBPF object is embedded in the userspace binary via:
```rust
let bpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tcp-state-monitor-ebpf"));
```

## Rust Toolchain

The eBPF crate needs the `bpf-unknown-none` target (or `bpfel-unknown-none`). Add a `rust-toolchain.toml` at the workspace root:

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
targets = ["bpfel-unknown-none"]
```

And a `.cargo/config.toml` in the workspace root:

```toml
[build]
# default target for workspace (userspace uses host)

[target.bpfel-unknown-none]
rustflags = ["-C", "link-arg=--btf"]
```

## Verify by running

After build:
```bash
cargo build --release 2>&1
```

The build must succeed with no errors. Do not actually run the binary (requires root + Linux eBPF).

## Code Standards

- No `unwrap()` in userspace main loop — use `?` or `match` with proper error messages
- All public types in common crate get doc comments
- Use `eprintln!` for errors, `println!` for events
- No unsafe outside of the eBPF crate (Aya handles it there)
- `cargo clippy` clean
