use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=ebpf/src/main.rs");

    // 只在 Linux 平台编译 eBPF 程序
    if cfg!(target_os = "linux") {
        // 编译 eBPF 程序
        let ebpf_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("ebpf");

        println!("cargo:warning=编译 eBPF 程序...");

        let status = Command::new("cargo")
            .args(&[
                "build",
                "--release",
                "--target=bpfel-unknown-none",
                "-Z", "build-std=core",
            ])
            .current_dir(&ebpf_dir)
            .env("RUSTFLAGS", "-C link-arg=--disable-memory-builtins -C linker-plugin-lto")
            .status();

        match status {
            Ok(status) if status.success() => {
                println!("cargo:warning=✅ eBPF 程序编译成功");
            }
            Ok(status) => {
                println!("cargo:warning=⚠️  eBPF 程序编译失败: {}", status);
                // 不要因为 eBPF 编译失败而导致整个构建失败
                // 程序会在运行时检测并降级到传统模式
            }
            Err(e) => {
                println!("cargo:warning=⚠️  无法执行 eBPF 编译: {}", e);
            }
        }
    }
}
