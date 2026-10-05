//! Temporary reverse-engineering helper: disassemble an arbitrary offset range
//! relative to _text. Used when a function is absent from kallsyms (arm64
//! syscall wrappers are unnamed locals) and must be located by behavior
//! instead of by symbol name.
//!
//! usage: cargo run --release --example disasm_range -- <boot.img> <start_hex> [len_hex]

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::disasm::disassemble_range;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: disasm_range <boot.img> <start_hex> [len_hex]");
        std::process::exit(2);
    });
    let start = usize::from_str_radix(
        &args.next().unwrap_or_else(|| {
            eprintln!("usage: disasm_range <boot.img> <start_hex> [len_hex]");
            std::process::exit(2);
        }),
        16,
    )
    .expect("start hex");
    let len = args
        .next()
        .map(|v| usize::from_str_radix(&v, 16).expect("len hex"))
        .unwrap_or(0x400);

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");

    println!(
        "=== range _text+0x{start:x} .. _text+0x{:x} (base {base:#x}) ===",
        start + len
    );
    match disassemble_range(&boot.kernel, start, start + len) {
        Ok(lines) => {
            for (i, line) in lines.iter().enumerate() {
                println!("{:04x}: {line}", start + i * 4);
            }
        }
        Err(e) => eprintln!("disasm failed: {e}"),
    }
}
