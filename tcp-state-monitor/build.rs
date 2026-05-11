use aya_build::{Package, Toolchain, build_ebpf};

fn main() {
    build_ebpf(
        [Package {
            name: "tcp-state-monitor-ebpf",
            root_dir: "../tcp-state-monitor-ebpf",
            ..Package::default()
        }],
        Toolchain::default(),
    )
    .unwrap();
}
