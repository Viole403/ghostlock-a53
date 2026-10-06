# Port the Exynos A53 mm_struct reclaim from Root-My-Galaxy-Payloads

L 级改动：攻击关键路径（heap prepare / KernelSnitch reclaim）。

## Motivation

A53 5.10 上首次真机运行（见 `docs/analysis/device-gates/ROOT-A536EXXSMGZE2-01.md`）显示本仓库的
`prepare_kernel_page` 在该 SoC 上必然失败：`mm_struct leaked=0xffffffffffffffff`，15 次重试全灭，
`Write 1 failed`。同一台设备上，Root-My-Galaxy-Payloads 的
`src/targets/a53x-A536EXXSNGZG3/page.c` 稳定成功（`PAGE_LEAK_GROUP_SELECTED` → `ARW_OK` → `ROOT_OK`）。

已确认 **不是常量问题**：

| 常量 | GZG3 profile | 本仓库 A53 分支 | 真机 |
| --- | --- | --- | --- |
| `KIMAGE_TEXT_BASE` | `0xffffffc008000000` | 同 | 一致（boot.img header `text_offset=0`） |
| `PHYS_OFFSET` | `0x80000000` | 同 | 一致（`memory@80000000`） |
| `MM_STRUCT_SZ` | `0x3c0` | 同（`mm_struct_sz=960`） | — |
| `MM_ORDER` | `3` | 同 | — |
| physmap 双窗口 | normal 区，实测 slab 在 `0xffffff8847018000` | 已按 +`0x40000000000` 换算 | 一致 |

差的是**算法**，不是参数。

## 差异分析

| | 本仓库 `prepare_kernel_page` | `page.c` |
| --- | --- | --- |
| pass 数 | 1 次 `context_scan` | 2 次：先 bruteforce 拿 1 个 mm，再 `collect_full_normal_group` 反复尝试 |
| 目标 | 单个 `last_mm_struct` | `batch = ORDER3_SIZE/MM_STRUCT_SZ` 个 mm，**同一个 order-3 slab** |
| zone | 两个窗口全扫 | 只接受 normal；DMA32 直接 skip |
| 判定 | `leaked != -1` 且落在 direct map | `match_page()`：候选在**所有** collision futex 下 hash 相同 |
| 压力 | `sendmsg` × `SKB_RECLAIM_SENDS` | `drain_group()`：24 个 trigger batch（816 ref）制造 drain pressure，**之后**才释放目标 slab 尾部 |
| hint 复用 | 无 | `hint` 命中时 `collisions=2 / passes=2`，未命中回退 `4/1` |

真机日志佐证 DMA32 不可靠：
`PAGE_LEAK_GROUP_SELECTED base=0xffffff8847018000 zone=normal`。

## 可行性：API 已齐备（先前判断有误）

`page.c` 用的是 staged C API，本仓库用同名不同名的 C++ 封装。逐一映射后确认**全部已存在**：

| page.c | 本仓库 |
| --- | --- |
| `kernelsnitch_setup` | `context_init` |
| `kernelsnitch_find_collisions` | `context_find_collisions` |
| `kernelsnitch_bruteforce` | `context_scan` |
| `kernelsnitch_found_collisions` | `context_has_collisions` |
| `kernelsnitch_cleanup` | `context_destroy` |
| `ks->mm_struct` | `context_result(ks)` |
| `futex_hash(addr, cand)` | `futex_hash_context_bucket(&ks->futex_hash, …)` |
| `match_page()` | `__mm_candidate_matches()`（语义相同） |

`kernelsnitch_shared_state` 本身已是可写字段（`mm_struct` / `found` / `collisions` / `futex_addrs` /
`times`），hint 复用所需的「写 `mm_struct` + 置 `found`」不需要新接口。

结论：**这是 driver 层移植，不需要改写 `src/core/kernelsnitch/`**（AGENTS.md 禁止改写的部分保持原样）。

## Implementation

1. **`src/core/support/a53_reclaim.{hpp,cpp}`（新增）**
   移植 `collect_full_normal_group` 与 `drain_group`：
   - `zone_of()` / `valid_mm()`：normal 区判定 + slot 对齐 `MM_STRUCT_SZ`
   - `match_page()`：复用 `__mm_candidate_matches` 语义，按 `base` 分组收集
   - `collect_full_normal_group()`：最多 `A53_PAGE_SCAN_MAX=256` 次尝试；DMA32 命中时按
     `A53_DMA32_SKIP_SLABS=8 × batch` 持有后丢弃
   - `drain_group()`：`A53_TRIGGER_SLABS=24 × batch = 816` ref，`sleep 1s`，再释放目标尾部
   - hint 复用：命中用 `collisions=2`、未命中 `4`
2. **`src/core/kernel/constants.hpp`（A53 分支）**
   补齐 `A53_PAGE_SCAN_MAX=256`、`A53_DMA32_SKIP_SLABS=8`、`A53_TRIGGER_SLABS=24`。
3. **`src/core/support/util.cpp`**
   `prepare_kernel_page` 在 A53 构建下改走新 driver；非 A53 分支保持原逻辑不动。
4. **`src/core/kernel/target_constants.hpp`**
   扫描窗口收敛到 normal 区（本仓库两个窗口中位于高位的那个），DMA32 窗口保留但不接受结果。

## Verify

1. `make -C src native-host-tests` + `make -C src host-attack-dataflow-test`（不得回归）
2. 静态 assert：A53 两个窗口、SKB 常量、trigger 数量
3. `cmp_disasm`：8 个攻击函数对已确认基线（commit `8931346` 构建产物）要求 IDENTICAL
4. **真机门禁**：冷启动、单 route、KernelSU 未加载；日志需出现
   `A53_GROUP_SELECTED zone=normal` → `A53_TRIGGER_READY refs=816` → `ARW_OK` → `ROOT_OK`
5. 失败时必须能区分：DMA32 命中（应 skip）/ slab 未填满 / scan 未找到

## Risk

- 若 GZE2 与 GZG3 在 SLUB 行为上有差异，`drain_group` 的时序需按真机日志调整
- `find_consts.py` / probe 产物不入库
- 真机门禁前先确认可用刷写路径（历史上出现过一次意外重启）

## Out of scope

- 不改 `src/core/kernelsnitch/**`
- 不改 route / payload 编码
- 不做 KernelSU 持久化（`vermagic` 为 GZG3，GZE2 需另行 patch）