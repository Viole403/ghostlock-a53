//! Temporary helper: harvest `task_struct` offsets from a `task_struct *` argument.
//!
//! Complements `harvest_task_offsets`, which anchors on `current_task` and so
//! cannot see fields only ever touched through a function argument. On 5.10 the
//! PI/race fields (`pi_waiters`, `pi_top_task`, `prio`, `normal_prio`) are only
//! reachable that way, because the rtmutex code takes `p` as x0.
//!
//! Safety: arg0 is trusted as a `task_struct *` only for functions listed in
//! `TASK_ARG0`, each chosen because the kernel passes the task pointer first.
//! Offsets are cross-checked against the `current`-anchored values already
//! confirmed (`flags` 0x18, `real_cred` 0x778, `cred` 0x780, `pi_lock` 0x86c,
//! `pi_blocked_on` 0x898); a mismatch means the arg0 assumption was wrong.
//!
//! usage: cargo run --release --example harvest_arg0_offsets -- <boot.img>

use std::collections::BTreeMap;
use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{relative_symbols, unique_offset_optional};
use ghostlock_extract::disasm::disassemble_range;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

/// (symbol, what its x0 is, expected cross-check offsets)
const TASK_ARG0: &[(&str, &str, &[u64])] = &[
    ("rt_mutex_setprio", "struct task_struct *p", &[0x18]),
    (
        "rt_mutex_adjust_prio_chain",
        "struct task_struct *p",
        &[0x18],
    ),
    ("rt_mutex_effective_prio", "struct task_struct *p", &[0x18]),
    ("sched_priority_", "struct task_struct *p", &[0x18]),
    ("sched_shift", "struct task_struct *p", &[0x18]),
    ("pick_next_task", "struct task_struct *p", &[]),
    ("rt_mutex_setprio_locked", "struct task_struct *p", &[0x18]),
    ("update_curr", "void (uses current)", &[]),
    ("__schedule", "void (uses current)", &[0x780, 0x86c, 0x898]),
];

/// Values already confirmed, for reporting cross-anchor agreement.
const CONFIRMED: &[(&str, u64)] = &[
    ("flags", 0x18),
    ("real_cred", 0x778),
    ("cred", 0x780),
    ("pi_lock", 0x86c),
    ("pi_blocked_on", 0x898),
];

fn operands(line: &str) -> &str {
    line.split_once(' ').map(|(_, r)| r).unwrap_or("")
}

fn imm_of(s: &str) -> Option<u64> {
    let at = s.find("#0x")?;
    let tail = &s[at + 3..];
    let end = tail
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(tail.len());
    u64::from_str_radix(&tail[..end], 16).ok()
}

fn mem_base_reg(s: &str) -> Option<String> {
    let open = s.find('[')?;
    let after = &s[open + 1..];
    let close = after.find(']')?;
    let reg: String = after[..close]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    (reg.starts_with('x') && reg.len() == 2).then_some(reg)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: harvest_arg0_offsets <boot.img>");
        std::process::exit(2);
    });

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let pair = btf_at.as_ref().map(|(o, b)| (*o, b.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let (rel, sorted) = relative_symbols(&ks.symbols, base);

    println!("# task_struct offsets via task_struct* argument (x0)");
    println!("# _text = 0x{base:016x}\n");

    // offset -> functions that touched it
    let mut hits: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    // offsets seen by BOTH this pass and the current-anchored pass
    let mut corroborated: Vec<(u64, String)> = Vec::new();

    for (symbol, arg0, expect) in TASK_ARG0 {
        let Some(off) = unique_offset_optional(&rel, symbol) else {
            println!("{symbol}: <absent>");
            continue;
        };
        let start = off as usize;
        let stop = sorted
            .iter()
            .find(|o| **o as usize > start)
            .map(|o| (*o as usize).min(start + 0x2000))
            .unwrap_or(start + 0x2000);
        let Ok(lines) = disassemble_range(&boot.kernel, start, stop) else {
            continue;
        };

        // x0 is the task pointer. Copies of it inherit the taint; address
        // computations (`add Rd, x0, #imm`) terminate it and yield a field
        // address, which is exactly the offset we want to record.
        let mut tainted: Vec<String> = vec!["x0".into()];
        let mut found: Vec<u64> = Vec::new();

        for raw in &lines {
            let line = raw.trim();
            let ops = operands(line);

            if line.starts_with("mov") {
                let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
                if parts.len() == 2 {
                    let dst = parts[0].split_whitespace().next().unwrap_or("");
                    let src = parts[1].split_whitespace().next().unwrap_or("");
                    if tainted.iter().any(|t| t == src) && !tainted.iter().any(|t| t == dst) {
                        tainted.push(dst.to_string());
                        continue;
                    }
                    // A plain move INTO a tainted reg re-points it at something
                    // else; drop it unless it came from another tainted reg.
                    if tainted.iter().any(|t| t == dst) && !tainted.iter().any(|t| t == src) {
                        tainted.retain(|t| t != dst);
                        continue;
                    }
                }
                continue;
            }

            let (src, imm, is_addr) = if let Some(r) = mem_base_reg(ops) {
                (Some(r), imm_of(ops), false)
            } else if line.starts_with("add") {
                let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
                if parts.len() < 3 {
                    continue;
                }
                (
                    parts[1].split_whitespace().next().map(str::to_string),
                    imm_of(parts[2]),
                    true,
                )
            } else {
                continue;
            };

            let (Some(src), Some(imm)) = (src, imm) else {
                continue;
            };
            if !tainted.iter().any(|t| *t == src) {
                continue;
            }
            /* Both shapes are real task_struct offsets: `add Rd, x0, #imm` forms a
             * field address, and `[x0, #imm]` dereferences the field directly. */
            if !found.contains(&imm) {
                found.push(imm);
                hits.entry(imm).or_default().push((*symbol).to_string());
            }
            if !is_addr && expect.contains(&imm) && !corroborated.iter().any(|(o, _)| *o == imm) {
                corroborated.push((imm, (*symbol).to_string()));
            }
        }

        found.sort_unstable();
        found.dedup();
        let joined: Vec<String> = found.iter().map(|o| format!("0x{o:x}")).collect();
        println!("{symbol} @ +0x{off:x}   x0 = {arg0}");
        println!("    {}", joined.join(", "));
        let expect_txt: Vec<String> = CONFIRMED
            .iter()
            .filter(|(_, v)| expect.contains(v))
            .map(|(n, v)| format!("{n}=0x{v:x}"))
            .collect();
        if !expect_txt.is_empty() {
            println!("    cross-check targets present: {}", expect_txt.join(", "));
        }
    }

    println!("\n# --- offsets reached by >=2 arg0 functions ---");
    let mut cross: Vec<(u64, Vec<String>)> =
        hits.into_iter().filter(|(_, v)| v.len() >= 2).collect();
    cross.sort_by_key(|(o, _)| *o);
    for (off, who) in cross {
        println!("  0x{off:<5x}  {}", who.join(", "));
    }

    if !corroborated.is_empty() {
        println!("\n# --- corroborated against current-anchored pass ---");
        for (off, who) in &corroborated {
            let name = CONFIRMED
                .iter()
                .find(|(_, v)| *v == *off)
                .map(|(n, _)| *n)
                .unwrap_or("?");
            println!("  0x{off:<5x} {name:<14} also seen in {who}");
        }
    }
}
