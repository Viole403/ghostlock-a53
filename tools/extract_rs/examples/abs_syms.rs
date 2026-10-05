//! Temporary helper: print absolute kallsyms virtual addresses.
//!
//! The A53 port needs `_text`'s absolute VA to line the tracefs slide oracle up
//! with the live `sched_blocked_reason` caller pointer. The other examples all
//! rebase onto `_text`, which hides exactly the number we want.
//!
//! usage: cargo run --release --example abs_syms -- <boot.img> [sym...]

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: abs_syms <boot.img> [sym...]");
        std::process::exit(2);
    });
    let wanted: Vec<String> = args.collect();

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let pair = btf_at.as_ref().map(|(o, b)| (*o, b.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, pair).expect("kallsyms recovery");

    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    println!("_text (absolute VA) = 0x{base:016x}");
    println!("_text (relative)    = 0x0");
    println!("total symbols       = {}", ks.symbols.len());

    let names: Vec<&str> = if wanted.is_empty() {
        vec![
            "_text",
            "_end",
            "worker_thread",
            "kthread",
            "schedule",
            "schedule_timeout",
            "__schedule",
            "init_task",
            "init_cred",
            "init_stack",
            "current_task",
            "remove_waiter",
            "rt_mutex_start_proxy_lock",
            "futex_requeue",
            "start_kernel",
            "system_unbound_wq",
            "workqueue_init",
            "call_usermodehelper_exec_work",
            "kernel_init",
        ]
    } else {
        wanted.iter().map(String::as_str).collect()
    };

    println!(
        "\n{:<36} {:>20} {:>14}",
        "symbol", "absolute VA", "rel to _text"
    );
    for name in names {
        match kallsyms::unique(&ks.symbols, name) {
            Some(va) => println!("{name:<36} 0x{va:016x}   0x{:x}", va.wrapping_sub(base)),
            None => match ks.symbols.get(name) {
                Some(v) => println!("{name:<36} (not unique: {v:?})"),
                None => println!("{name:<36} <absent>"),
            },
        }
    }
}
