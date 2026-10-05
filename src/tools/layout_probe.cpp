/* Layout probe: materialises the selected address layout into .rodata.
 *
 * The A53 gate needs to prove that GHOSTLOCK_TARGET_A53_5_10 actually
 * selects the VA_BITS=39 constants, and that it does so for every
 * translation unit built by the Makefile. Reconstructing the value out of a
 * disassembly listing is fragile -- clang splits a 64-bit immediate across
 * mov/movk differently depending on surrounding code, and an earlier
 * version of this check failed for exactly that reason.
 *
 * Compiling this probe with the same flags as the real sources and reading
 * its .rodata is deterministic: the constant is the only thing in the
 * section, so its bytes are unambiguous.
 *
 * The VA48 and VA39 layouts differ only in the third byte of the low word
 * (0x80 vs 0x08), which is what the gate asserts on.
 */
#include "../core/kernel/target_constants.hpp"

extern "C" __attribute__((used, section(".rodata"))) const unsigned long
    ghostlock_probe_text_base = ghostlock::target::address::kImageTextBase;

extern "C" __attribute__((used, section(".rodata"))) const unsigned long
    ghostlock_probe_page_offset = ghostlock::target::address::kPageOffset;