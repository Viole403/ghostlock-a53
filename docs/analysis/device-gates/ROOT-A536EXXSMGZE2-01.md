# ROOT-A536EXXSMGZE2-01 — first root on SM-A536E / A536EXXSMGZE2

| Field | Value |
| --- | --- |
| Device | `SM-A536E` (a53xnsxx, Exynos 1280 / s5e8825) |
| Firmware | `A536EXXSMGZE2` |
| Kernel | `5.10.237-android12-9-31999025-abA536EXXSMGZE2` |
| `uname -r` | `5.10.237-android12-9-31999025-abA536EXXSMGZE2` |
| Date | 2026-10-06 |
| Result | **ROOT achieved** — `ROOT_OK`, `ARW_OK`, `PATCH_OK` |

## What was run

The published device-tested payload
`BuSung-dev/Root-My-Galaxy-Payloads` → `artifacts/a53x-A536EXXSNGZG3/cve-2026-43499-app.so`
(SHA-256 `fb9b2e08adb8046f3ae0566cc0b10ae55c5bb72b0d04396a935141e242060fdf`), together with
the root helper built from the same revision's `src/su_daemon.c`, loaded through a
minimal `dlopen` shim. The payload self-starts from an ELF constructor.

The target profile used was the **GZG3** one, not a GZE2 profile. It transferred
without modification; the constants it depends on are identical on this firmware:

| Constant | GZG3 profile | GZE2 (independently derived here) |
| --- | --- | --- |
| `KIMAGE_TEXT_BASE` | `0xffffffc008000000` | same (from boot.img image header, `text_offset = 0`) |
| `PHYS_OFFSET` | `0x80000000` | same (from `/proc/device-tree/memory@80000000`) |
| `MM_STRUCT_SZ` | `0x3c0` | same |
| `MM_ORDER` | `3` | same |
| `CONFIG_ARM64_VA_BITS` | (48 layout implied by its aliases) | `39`, on this device |

KASLR slide was resolved live at `0x1c0000`, inside their `MAX_PHYSICAL_SLIDE`
of `0x3f00000`. The mm_struct slab was found in the **normal** zone at
`0xffffff8847018000` — 512 GiB above the page offset, which is the second of the
two physmap windows.

## Evidence

```
PAGE_LEAK_GROUP_SELECTED base=0xffffff8847018000 zone=normal
PAGE_LEAK_TRIGGER_READY pages=24 refs=816 s2=854 cpu=0
PAGE_LEAK_TARGET_TAIL_FREE pages=24 refs_held=793 cpu=0
PAGE_LEAK_SKB_SENT requested=256 full=250 last=36480 errno=0
arw slots=1 fops=8/0xffffff8847018100 scratch=8/... owner=8 selinux=8/8/0x10000
ARW_OK
PATCH_OK usersize=0x47018a00
ROOT_OK
chain ready slide=0x1c0000 detached=1
A536_APP_ROOT_PROOF uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

Post-run state on device: `/sys/fs/selinux/enforce` = `0` (was `1`),
`getenforce` = `Permissive`, `rmg-root -c id` returns
`uid=0(root) ... context=u:r:kernel:s0`, and `/proc/iomem` plus `/proc/kallsyms`
become readable (301,635 kallsyms lines captured).

## What this establishes for this repository

1. **`kernel_phys_load = 0x80000000` is correct for this firmware.** Confirmed
   independently from the DT node and the image header, and by a live run whose
   derived addresses all resolved.
2. **The dual physmap window is correct**, and the mm_structs are in the high
   (normal) window — the low window was never where they were.
3. **The blocking gap in this port is the reclaim algorithm, not any constant.**
   `Root-My-Galaxy-Payloads` `src/targets/a53x-A536EXXSNGZG3/page.c` builds a full
   mm_struct slab group (24 trigger batches, 816 refs), applies drain pressure,
   and only then frees the target slab's tail. It needs the staged KernelSnitch C
   API (`kernelsnitch_setup` / `find_collisions` / `bruteforce` / `cleanup`), which
   this repository's `src/core/kernelsnitch/` does not expose — it offers a single
   opaque `KernelSnitchOwner::create`. The interleaving points page.c depends on
   therefore do not exist here, and `AGENTS.md` forbids rewriting that directory.

## Device safety

One unrelated reboot occurred earlier in this session, during an
`mm_struct_sz` sweep that produced no kernel writes. The successful run above
completed with the device up and no reboot. Root here is **volatile**: it does
not survive a reboot.
