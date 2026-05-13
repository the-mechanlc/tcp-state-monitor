# tcp-state-monitor

A Linux CLI tool that monitors TCP state transitions in real time using eBPF. Built with [Rust](https://www.rust-lang.org/) and [Aya](https://aya-rs.dev/).

Hooks into the kernel's `tracepoint/sock/inet_sock_set_state` — zero overhead on connections you're not watching, no kernel module required.

```
[PID 1234   / curl           ]  192.168.1.5:54321 -> 142.251.163.102:443   SYN_SENT -> ESTABLISHED
[PID 1234   / curl           ]  192.168.1.5:54321 -> 142.251.163.102:443   ESTABLISHED -> FIN_WAIT1
```

## Requirements

- Linux kernel 4.18+ (eBPF ring buffer support)
- `root` / `sudo` (required to load eBPF programs)
- Rust nightly toolchain (see build steps)
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker)

## Build

### 1. Install Rust nightly + BPF target

```bash
rustup toolchain install nightly --component rust-src
rustup target add --toolchain nightly bpfel-unknown-none
```

### 2. Install bpf-linker

```bash
cargo install bpf-linker
```

### 3. Clone and build

```bash
git clone https://github.com/the-mechanlc/tcp-state-monitor
cd tcp-state-monitor
cargo build --release
```

The eBPF program is compiled and embedded into the binary automatically via `build.rs`.

## Usage

```bash
sudo ./target/release/tcp-state-monitor [OPTIONS]
```

### Options

| Flag | Description | Example |
|------|-------------|---------|
| `--addr <IP>` | Filter by source **or** destination IPv4 address | `--addr 192.168.1.5` |
| `--port <PORT>` | Filter by source **or** destination port | `--port 443` |
| `--state <STATE>` | Only show transitions **into** this state | `--state ESTABLISHED` |
| `--pid <PID>` | Filter by process ID | `--pid 1234` |

Multiple filters are **AND**-ed together. No filters = show all TCP state changes system-wide.

### Examples

**Watch all TCP activity:**
```bash
sudo ./target/release/tcp-state-monitor
```

**Watch only HTTPS connections (port 443):**
```bash
sudo ./target/release/tcp-state-monitor --port 443
```

**Watch connections to/from a specific host:**
```bash
sudo ./target/release/tcp-state-monitor --addr 142.251.163.102
```

**Find all connections reaching ESTABLISHED:**
```bash
sudo ./target/release/tcp-state-monitor --state ESTABLISHED
```

**Watch a specific process:**
```bash
sudo ./target/release/tcp-state-monitor --pid $(pgrep nginx)
```

**Combine filters — ESTABLISHED connections on port 443:**
```bash
sudo ./target/release/tcp-state-monitor --port 443 --state ESTABLISHED
```

### TCP States

| State | Description |
|-------|-------------|
| `ESTABLISHED` | Connection is open and active |
| `SYN_SENT` | Client sent SYN, waiting for SYN-ACK |
| `SYN_RECV` | Server received SYN, sent SYN-ACK |
| `FIN_WAIT1` | Active close initiated |
| `FIN_WAIT2` | Waiting for remote FIN |
| `TIME_WAIT` | Waiting for late packets (2×MSL) |
| `CLOSE` | Connection fully closed |
| `CLOSE_WAIT` | Remote end closed, waiting for local close |
| `LAST_ACK` | Waiting for final ACK |
| `LISTEN` | Server is listening for connections |
| `CLOSING` | Both sides closing simultaneously |

## Output Format

```
[PID <pid> / <comm>] <src_ip>:<src_port> -> <dst_ip>:<dst_port>  <OLD_STATE> -> <NEW_STATE>
```

- **PID / comm** — process that triggered the state change (may show `swapper/N` for kernel-initiated transitions like the ACK on `SYN_SENT → ESTABLISHED`)
- **src/dst** — source and destination IPv4 addresses and ports
- **states** — previous and new TCP state

## Project Structure

```
tcp-state-monitor/
├── Cargo.toml                      # workspace root
├── tcp-state-monitor/              # userspace binary
│   ├── Cargo.toml
│   ├── build.rs                    # compiles the eBPF crate
│   └── src/main.rs                 # CLI, ring buffer consumer, output
├── tcp-state-monitor-ebpf/         # eBPF program (no_std)
│   ├── Cargo.toml
│   └── src/main.rs                 # tracepoint hook, writes TcpEvent to RingBuf
└── tcp-state-monitor-common/       # shared types
    ├── Cargo.toml
    └── src/lib.rs                  # TcpEvent struct, tcp_state_name()
```

## Roadmap

- [ ] IPv6 support
- [ ] `--output json` for structured output / piping
- [ ] `--comm <name>` filter by process name
- [ ] Aggregate mode: connection counts per state
