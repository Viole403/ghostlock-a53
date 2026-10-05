//! Temporary helper: harvest `task_struct` field offsets from the kernel text.
//!
//! This A53 kernel ships no BTF and no DWARF (`CONFIG_DEBUG_INFO_BTF` unset and
//! the Image is stripped), so struct layouts cannot be read out of metadata.
//! They can still be recovered from the code itself: on arm64 the current task
//! pointer lives in a per-CPU slot read with `mrs xN, s3_0_c4_c1_0`, so every
//! `[xN, #imm]` access that follows is a `task_struct` field offset. Running
//! that scan across functions with known semantics labels the offsets.
//!
//! This is more authoritative than a header guess: it reads the offsets the
//! shipped kernel actually compiled with.
//!
//! usage: cargo run --release --example harvest_task_offsets -- <boot.img>

use std::collections::BTreeMap;
use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{relative_symbols, unique_offset_optional};
use ghostlock_extract::disasm::disassemble_range;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

/// Functions whose semantics identify the field they touch.
const ANCHORS: &[(&str, &str)] = &[
    ("commit_creds", "task->cred (store) / task->real_cred"),
    ("override_creds", "task->cred (store)"),
    ("revert_creds", "task->cred (store)"),
    ("prepare_creds", "task->cred / real_cred"),
    ("copy_creds", "task->cred (load)"),
    ("selinux_cred_prepare", "task->cred (load)"),
    ("do_seccomp", "task->seccomp"),
    ("do_exit", "task->tasks / exit_state / flags"),
    ("find_get_task_by_vpid", "task->tasks (list head)"),
    ("rt_mutex_adjust_prio_chain", "pi_waiters / pi_top_task"),
    ("rt_mutex_slowlock", "pi_lock / pi_waiters"),
    ("rt_mutex_setprio", "prio / normal_prio / pi_waiters"),
    ("ttwu_do_activate", "pi_blocked_on / state"),
    ("remove_waiter", "pi_lock / pi_blocked_on"),
    ("dump_stack", "task->comm"),
    ("kthread", "task->comm / flags"),
];

/// Strip the mnemonic and return the operand text.
fn operands(line: &str) -> &str {
    line.split_once(' ').map(|(_, r)| r).unwrap_or("")
}

/// `#0xIMM` value, if present.
fn imm_of(s: &str) -> Option<u64> {
    let at = s.find("#0x")?;
    // Skip the whole "#0x" marker; stopping after "#" would leave "0x.." whose
    // 'x' ends the hex run immediately and every offset would parse as 0.
    let tail = &s[at + 3..];
    let end = tail
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(tail.len());
    u64::from_str_radix(&tail[..end], 16).ok()
}

/// Register a `[reg, ...]` memory operand refers to.
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
        eprintln!("usage: harvest_task_offsets <boot.img>");
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

    println!("# task_struct offsets harvested from {boot_path}");
    println!("# _text = 0x{base:016x}");
    println!("# taint source: `mrs xN, s3_0_c4_c1_0` == per-CPU current_task\n");

    let mut hits: BTreeMap<u64, Vec<String>> = BTreeMap::new();

    for (symbol, meaning) in ANCHORS {
        let Some(off) = unique_offset_optional(&rel, symbol) else {
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

        let mut tainted: Vec<String> = Vec::new();
        let mut found: Vec<u64> = Vec::new();

        for raw in &lines {
            let line = raw.trim();
            let ops = operands(line);

            // Seed / refresh the taint.
            if line.starts_with("mrs") && ops.contains("s3_0_c4_c1_0") {
                if let Some(reg) = ops
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .split_whitespace()
                    .next()
                {
                    if !tainted.contains(&reg.to_string()) {
                        tainted.push(reg.to_string());
                    }
                }
                continue;
            }

            let (dst, src, imm, kind) = if let Some(base_reg) = mem_base_reg(ops) {
                // ldr/str/ldur/stur/ldp/stp: `xD, [xB, #imm]`
                let mut parts = ops.split(',').map(str::trim);
                let _dst = parts.next().unwrap_or("");
                let _br = parts.next().unwrap_or("");
                (None, Some(base_reg), imm_of(ops), "mem")
            } else if line.starts_with("add") || line.starts_with("sub") {
                let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
                if parts.len() < 3 {
                    continue;
                }
                (
                    parts[0].split_whitespace().next().map(str::to_string),
                    parts[1].split_whitespace().next().map(str::to_string),
                    imm_of(parts[2]),
                    "addr",
                )
            } else {
                (None, None, None, "")
            };

            if kind.is_empty() {
                continue;
            }

            let Some(imm) = imm else { continue };
            let Some(src) = src else { continue };
            let Some(reg) = src.strip_prefix('x') else {
                continue;
            };
            if reg.len() != 2 || !tainted.iter().any(|t| t.as_str() == src) {
                continue;
            }
            // Exclude SP-relative and any explicit base write.
            if ops.contains("[sp") {
                continue;
            }
            if !found.contains(&imm) {
                found.push(imm);
                hits.entry(imm).or_default().push((*symbol).to_string());
            }

            // Deliberately no taint inheritance through `add`: `add xD, xB, #imm`
            // yields &task->field, not a second task base. Propagating the taint
            // would report field-relative displacements (pi_lock-relative 0x880)
            // as if they were task_struct offsets.
            let _ = &dst;
        }

        if !found.is_empty() {
            let mut v = found;
            v.sort_unstable();
            let joined: Vec<String> = v.iter().map(|o| format!("0x{o:x}")).collect();
            println!("{symbol} @ +0x{off:x}   [{meaning}]");
            println!("    {}", joined.join(", "));
        }
    }

    println!("\n# --- offsets touched by >=2 anchors (higher confidence) ---");
    let mut cross: Vec<(u64, Vec<String>)> =
        hits.into_iter().filter(|(_, v)| v.len() >= 2).collect();
    cross.sort_by_key(|(o, _)| *o);
    for (off, who) in cross {
        println!("  0x{off:<5x}  {}", who.join(", "));
    }
}
