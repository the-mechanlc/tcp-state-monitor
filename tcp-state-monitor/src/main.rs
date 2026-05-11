use std::net::Ipv4Addr;

use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::TracePoint,
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tcp_state_monitor_common::{tcp_state_name, TcpEvent};
use tokio::io::unix::AsyncFd;

#[derive(Parser, Debug)]
#[command(about = "Monitor TCP state transitions via eBPF")]
struct Args {
    /// Filter by src OR dst IPv4 address
    #[arg(long)]
    addr: Option<std::net::Ipv4Addr>,

    /// Filter by src OR dst port
    #[arg(long)]
    port: Option<u16>,

    /// Only show transitions INTO this state (e.g. ESTABLISHED, TIME_WAIT)
    #[arg(long)]
    state: Option<String>,

    /// Filter by PID
    #[arg(long)]
    pid: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    let bpf_bytes =
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tcp-state-monitor"));

    let mut ebpf = Ebpf::load(bpf_bytes)?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("tcp_state_monitor")
        .ok_or_else(|| anyhow::anyhow!("eBPF program 'tcp_state_monitor' not found"))?
        .try_into()?;
    program.load()?;
    program.attach("sock", "inet_sock_set_state")?;

    info!("Attached tracepoint sock/inet_sock_set_state");

    let ring_buf = ebpf
        .map_mut("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("map 'EVENTS' not found"))?;
    let ring_buf = RingBuf::try_from(ring_buf)?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            let data = item.as_ref();
            if data.len() < std::mem::size_of::<TcpEvent>() {
                eprintln!("short event: {} bytes", data.len());
                continue;
            }
            let event: TcpEvent = unsafe {
                std::ptr::read_unaligned(data.as_ptr() as *const TcpEvent)
            };
            if let Err(e) = handle_event(&event, &args) {
                eprintln!("error handling event: {e}");
            }
        }
        guard.clear_ready();
    }
}

fn handle_event(event: &TcpEvent, args: &Args) -> anyhow::Result<()> {
    let src_addr = Ipv4Addr::from(u32::from_be(event.src_addr));
    let dst_addr = Ipv4Addr::from(u32::from_be(event.dst_addr));
    let new_state_name = tcp_state_name(event.new_state);

    // Apply filters (all AND-ed).
    if let Some(filter_addr) = args.addr {
        if src_addr != filter_addr && dst_addr != filter_addr {
            return Ok(());
        }
    }
    if let Some(filter_port) = args.port {
        if event.src_port != filter_port && event.dst_port != filter_port {
            return Ok(());
        }
    }
    if let Some(ref filter_state) = args.state {
        if !new_state_name.eq_ignore_ascii_case(filter_state) {
            return Ok(());
        }
    }
    if let Some(filter_pid) = args.pid {
        if event.pid != filter_pid {
            return Ok(());
        }
    }

    let null_pos = event.comm.iter().position(|&b| b == 0).unwrap_or(16);
    let comm = std::str::from_utf8(&event.comm[..null_pos]).unwrap_or("?");

    println!(
        "[PID {:<6} / {:<15}] {:>15}:{:<5} -> {:>15}:{:<5}  {} -> {}",
        event.pid,
        comm,
        src_addr,
        event.src_port,
        dst_addr,
        event.dst_port,
        tcp_state_name(event.old_state),
        new_state_name,
    );

    Ok(())
}
