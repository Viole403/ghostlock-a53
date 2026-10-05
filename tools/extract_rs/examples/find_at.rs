//! Temporary helper: which function contains a given `_text`-relative offset.
//!
//! The tracefs `sched_blocked_reason` caller pointer resolves to a static offset
//! inside *some* kernel function. On 6.12 that is `worker_thread`'s return
//! address, but 5.10 lays the kworker sleep loop out differently, so the offset
//! has to be attributed by containment rather than assumed.
//!
//! usage: cargo run --release --example find_at -- <boot.img> <rel_offset>...

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: find_at <boot.img> <rel_offset>...");
        std::process::exit(2);
    });
    let wanted: Vec<u64> = args
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("offset must be hex"))
        .collect();

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let pair = btf_at.as_ref().map(|(o, b)| (*o, b.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let rel0 = base;

    // Flatten to (relative_offset, name) and sort, so containment is a scan.
    let mut flat: Vec<(u64, &str)> = Vec::with_capacity(ks.symbols.len());
    for (name, addrs) in &ks.symbols {
        for va in addrs {
            flat.push((va.wrapping_sub(rel0), name.as_str()));
        }
    }
    flat.sort_by_key(|(off, _)| *off);
    flat.dedup_by_key(|(off, _)| *off);

    println!("_text = 0x{base:016x}; {} symbols\n", flat.len());
    for target in wanted {
        // Nearest symbol at-or-before the target is the containing function.
        let idx = flat
            .partition_point(|(off, _)| *off <= target)
            .saturating_sub(1);
        let (off, name) = flat[idx];
        let next = flat.get(idx + 1).map(|(o, _)| *o).unwrap_or(0);
        let size = next.saturating_sub(off);
        println!("0x{target:08x}  ->  {name} +0x{:x}", target - off);
        println!(
            "            [{name} spans 0x{off:x}..0x{:x}, size 0x{size:x}]",
            off + size
        );
        println!("            within bounds: {}", target < off + size);
    }
}
