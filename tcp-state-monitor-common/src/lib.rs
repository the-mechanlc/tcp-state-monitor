#![no_std]

/// A TCP state transition event captured by the eBPF program.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEvent {
    /// PID of the process that owns the socket.
    pub pid: u32,
    /// Comm (process name), null-terminated, up to 16 bytes.
    pub comm: [u8; 16],
    /// Source IPv4 address in network byte order.
    pub src_addr: u32,
    /// Destination IPv4 address in network byte order.
    pub dst_addr: u32,
    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// Previous TCP state.
    pub old_state: u32,
    /// New TCP state.
    pub new_state: u32,
}

/// Returns the human-readable name for a TCP state number.
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
