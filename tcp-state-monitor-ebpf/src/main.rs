#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use tcp_state_monitor_common::TcpEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Offsets into the inet_sock_set_state tracepoint args struct.
// Layout (64-bit kernel):
//   0: u64  common fields (unused)
//   8: *const void skaddr
//  16: i32  oldstate
//  20: i32  newstate
//  24: u16  sport
//  26: u16  dport
//  28: u16  family
//  30: u16  protocol
//  32: [u8;4] saddr
//  36: [u8;4] daddr
//  40: [u8;16] saddr_v6
//  56: [u8;16] daddr_v6
const OFF_OLDSTATE: usize = 16;
const OFF_NEWSTATE: usize = 20;
const OFF_SPORT: usize = 24;
const OFF_DPORT: usize = 26;
const OFF_PROTOCOL: usize = 30;
const OFF_SADDR: usize = 32;
const OFF_DADDR: usize = 36;

const IPPROTO_TCP: u16 = 6;

#[tracepoint]
pub fn tcp_state_monitor(ctx: TracePointContext) -> i32 {
    match try_tcp_state_monitor(ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_state_monitor(ctx: TracePointContext) -> Result<(), i64> {
    let protocol = unsafe { ctx.read_at::<u16>(OFF_PROTOCOL)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }

    let old_state = unsafe { ctx.read_at::<i32>(OFF_OLDSTATE)? } as u32;
    let new_state = unsafe { ctx.read_at::<i32>(OFF_NEWSTATE)? } as u32;
    let sport = unsafe { ctx.read_at::<u16>(OFF_SPORT)? };
    let dport = unsafe { ctx.read_at::<u16>(OFF_DPORT)? };
    let saddr = unsafe { ctx.read_at::<u32>(OFF_SADDR)? };
    let daddr = unsafe { ctx.read_at::<u32>(OFF_DADDR)? };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpEvent {
        pid,
        comm,
        src_addr: saddr,
        dst_addr: daddr,
        src_port: u16::from_be(sport),
        dst_port: u16::from_be(dport),
        old_state,
        new_state,
    };

    if let Some(mut buf) = EVENTS.reserve::<TcpEvent>(0) {
        buf.write(event);
        buf.submit(0);
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
