# A53-01 — SM-A536E / A536EXXSMGZE2: reclaim port verified, race localised

Device: `RRCT403DMVR`, SM-A536E, firmware `A536EXXSMGZE2`,
`uname -r = 5.10.237-android12-9-31999025-abA536EXXSMGZE2`, Exynos 1280.
Binary: `daddde15451a4639b09b6da54b41d01c` (`-DGHOSTLOCK_TARGET_A53_5_10 -DGHOSTLOCK_DIAG`).
Log: `A53-RECLAIM-RACE-01.log`.

## Verdict

| Stage | Result |
| --- | --- |
| mm_struct group reclaim (the ported work) | **PASS** |
| Page validation (`payload_write_layout_*`) | **PASS** |
| PI-futex race | **FAIL** — localised to one call |
| Root via our code | not reached |

## Reclaim — PASS

Repeated across runs 2/3/4/6/7 and again here, with a different slab base each time:

```
A53_GROUP_SELECTED base=0xffffff892edf0000 zone=normal objects=34 attempts=256
A53_TRIGGER_READY slabs=24 refs=816
A53_TARGET_TAIL_FREE batch=34
prepare_kernel_page ok attempt=1
```

`prepare_kernel_page ok` is emitted only after **both**
`payload_write_layout_matches_request()` and
`payload_write_layout_accepts_page()` pass, i.e. the layout matches the write
request and the page stores an even byte over `selinux_state.initialized`.

## Three defects fixed to get here

1. **Wrong scan context.** The hunt reused the module-level `clone_leak_child()`,
   which drives the *outer* context's state machine rather than the per-hunt one.
   Symptom: repeated `assert(ks->state == ...): wrong state`.
2. **Leak child never reaped.** One orphan per attempt exhausted the process
   table. Symptom: `pthread_create failed: Try again`, `SYS_clone` EAGAIN cascade.
3. **`SKB_SEND_SIZE` 256x too large.** The Exynos tuning raises the send *count*,
   not the per-send size; upstream keeps two order-3 slabs (64 KiB).
   `prepare_kernel_page`'s shaping `sendmsg()` is blocking and its peer is never
   drained, so an 8 MiB send parks in `sock_wait_for_wmem` forever.
   Measured: 0% CPU, 1 thread, `wchan=sock_wait_for_wmem`.

## Address layout — our rebase was wrong, the device config was right

The physmap windows were previously rebased onto `0xffffffc000000000`, on the
assumption that `CONFIG_ARM64_VA_BITS=39` moves the linear map to the same place
the kernel image lives. It does not. From this kernel's own
`arch/arm64/include/asm/memory.h`:

```c
#define _PAGE_OFFSET(va)    (-(UL(1) << (va)))
#define PAGE_OFFSET         (_PAGE_OFFSET(VA_BITS))
```

| VA_BITS | PAGE_OFFSET |
| --- | --- |
| 39 | `0xffffff8000000000` |
| 48 | `0xffff000000000000` |

So `CONFIG_ARM64_VA_BITS=39` — which the device config states — predicts
`0xffffff8000000000` exactly, and the run that achieved root resolved slabs at
`0xffffff80...` / `0xffffff88...` and wrote through them. The kernel image is a
separate mapping near `KIMAGE_VADDR`, which is where `_text =
0xffffffc008000000` lives. **The config was correct; the rebase was the bug.**

This also corrects an earlier note in this repository that blamed
`/proc/config.gz` for describing a different kernel. It does not. The mistake was
conflating the image VA with the linear map. The resulting constants are
independently corroborated by `Meowkis/ghostlock-samsung-research/src/offsets/5.10.h`
(a different 39-bit-VA 5.10 device):

```
P0_PAGE_OFFSET              0xffffff8000000000
KERNELSNITCH_IDENTITY_START 0xffffff8000000000
KIMAGE_TEXT_BASE            0xffffffc008000000   (identical to ours)
PSELECT_WAITER_WORD_SHIFT   0
```

Scanning the old rebased windows pointed at unmapped memory, so no slab could
match — which is the same failure mode as the single-scan path, just earlier.

## Race — FAIL, localised

```
[route] creating waiter/owner/consumer
consumer thread running on cpu=1
[route] waiter parked; owner started          <- waiter parks; shift=0 is correct
[route] CMP_REQUEUE_PI ret=-1 errno=35        <- EDEADLK: the requeue fails
pselect route setup shift=0 page=ffffff892edf0000 fake_lock=ffffff892edf0000 ...
pselect pre-select attempt=1/1 compact=0 +0ms
pselect post-select attempt=1/1 compact=0 +202ms ret=5
<log ends; device reboots>
```

`waiter_shift = 0` is confirmed correct — the waiter reaches the parked state and
stays there. The failure is `FUTEX_CMP_REQUEUE_PI` returning `-1/EDEADLK`: the
waiter never migrates onto the fake lock, so the write primitive is never
established. `consumer_go` is armed *before* `select()` (step 448) and fires
concurrently, so the consumer still runs `sched_setattr` on the waiter and the
kernel walks forged PI state — which is what takes the device down.

**The earlier "dies before the route's first log" reading was a logging
artefact.** `timer_mark` does `fflush` + `fsync`; every other log only `fflush`es,
so a reboot discarded everything after the last fsync. `-DGHOSTLOCK_DIAG` now
fsyncs the race markers.

## Reboot mechanism

- `sys.boot.reason = reboot`, **not** `kernel_panic`
- `/sys/fs/pstore/` holds **no** entries, so no oops was recorded
- memory is not the constraint: sampled live at 200-500 MB free with 274 children
  and ~1100 total processes
- therefore the reboot is a watchdog/liveness reset, not an OOM

## Still open

- `FUTEX_CMP_REQUEUE_PI` returning `EDEADLK` on this kernel — the actual front line
- no `A536EXXSMGZE2` KernelSU module; upstream ships `A536EXXSNGZG3` (same SoC,
  different vermagic string). Only needed for KSU, not for uid-0.