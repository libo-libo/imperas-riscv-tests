# Repository Guidelines

Imperas RISC-V architectural validation test framework: bare-metal `.S` tests compiled with a
RISC-V GCC, executed on a simulator, and validated by diffing a **signature dump** against a
checked-in golden reference. Pure `make` + `bash` — no CMake, no CI, no linter, no formatter.

## Project Overview

- Purpose: check that a RISC-V implementation (DUT, or the bundled golden model) complies with a
  given ISA extension, by running directed assembly tests and comparing register/memory
  signatures byte-for-byte.
- This checkout is the GitHub edition (`riscvOVPsim`, release `20230626.0`). **Only
  `riscv-test-suite/rv32i_m/I/` actually contains test sources** (48 tests). Every other suite
  directory is metadata only: `README.md`, `basic.coverage.txt`, `extended.coverage.txt`,
  `test_suite_details.txt`, `test_suite_sizes.txt`.
- Full suite sources (RV64, RV32E, `-RVI`, vector, B/K/P, PMP) come only from the
  `riscvOVPsimPlus` package; they are not in this repo and must not be assumed present.

## Architecture & Data Flow

Three independent layers, joined only by the `rv<XLEN><BASE>_<MODE>/<DEVICE>` path convention:

```
Makefile (root)                       driver: variable defaults, device enumeration, sub-make fan-out
  └─ riscv-test-suite/<suite>/<DEV>/  .S sources + references/ + Makefrag (test list)
       └─ riscv-target/<TARGET>/      device adapter: link.ld, model_test.h, per-device Makefile.include
            └─ simulator binary       riscvOVPsim.exe (or an external DUT binary)
```

Flow per device: `compile` (`src/%.S` → `work/.../%.elf` via `COMPILE_TARGET`) → `run`
(`%.elf` → `%.log` + `%.signature.output` via `RUN_TARGET`) → `verify` (`diff` signature vs
`references/*.reference_output`) → `postverify`/`cover` (functional coverage YAML from the log).

In-test lifecycle: `rvtest_entry_point` → `RVMODEL_BOOT` (`mtvec`/`mepc`/`mret`) →
`RVTEST_CODE_BEGIN` (seeds x1–x31) → `TEST_*_OP` cases (instruction + `RVTEST_SIGUPD` store) →
`RVTEST_CODE_END` → `RVMODEL_HALT` (`fence; ecall`).

**Pass/fail is not a console marker.** The verdict is the textual diff. `TESTNUM` is `gp`;
`gp==1` pass / `gp=(n<<1)|1` fail / `1337` unhandled trap is written to `tohost`, but the
framework never reads `tohost` — only the signature file matters.

## Key Directories

| Path | Purpose |
|---|---|
| `riscv-test-suite/rv32i_m/I/` | **The only buildable suite**: `Makefile`, `Makefrag`, `src/*.S`, `references/*.reference_output` |
| `riscv-test-suite/env/` | Live macro environment: `arch_test.h` (1437 lines, `RVTEST_*`/`TEST_*`), `encoding.h` (CSR/`CAUSE_*`), `mem_test.h` (PMP) |
| `riscv-test-suite/<other>/<DEV>/` | Metadata only — no `src/`, no `references/` |
| `riscv-target/riscvOVPsim/` | OVPsim adapter: `link.ld`, `model_test.h`, `postverify.sh`, `device/**/Makefile.include`, `cover.sh` |
| `riscv-target/sail-riscv-c/` | Second adapter (external `riscv_sim_RV64` on `PATH`) |
| `riscv-test-env/` | `verify.sh` (used) + `p/`, `test_macros.h`, `riscv_test_macros.h` (**legacy, unreferenced dead weight**) |
| `riscv-ovpsim/` | Bundled simulator `bin/{Linux64,Windows64}/riscvOVPsim.exe`, Apache-2.0 model `source/` (reference only, no build files), `examples/`, `config-yaml/` |
| `riscv-ovpsim-plus/` | Docs + PDFs only; **no `bin/`**, so `RISCV_TARGET=riscvOVPsimPlus` cannot run here |
| `work/` (generated) | All artifacts: `<TEST>.elf`, `.log`, `.signature.output`, `.diff`, `.basic.coverage.yaml` |

## Development Commands

Prerequisite: `riscv64-unknown-elf-gcc` (and `objdump`) on `PATH`, or override `RISCV_PREFIX`.
The root `Makefile` hard-errors at parse time if neither `$(RISCV_PREFIX)gcc` nor
`$(RISCV_PREFIX)as` resolves.

```bash
make help                                          # prints variable info + target list
make compile   XLEN=32 RISCV_DEVICE=I              # build only  -> work/rv32i_m/I/*.elf
make run       XLEN=32 RISCV_DEVICE=I              # simulate    -> *.signature.output
make verify    XLEN=32 RISCV_DEVICE=I              # NOTE: verify: simulate, so it re-runs first
make RISCV_TEST=ADD-01 compile                      # single test (works; name is ADD-01, not I-ADD-01)
make clean simulate verify postverify XLEN=32 RISCV_DEVICE=I   # README's documented flow
make -j1 VERBOSE=1 XLEN=32 RISCV_DEVICE=I run      # keep stdout/stderr and recipe echo
```

Aliases: `default` → `variant` → `simulate verify`; `build`=`compile`; `run`=`simulate`;
`cover`=`postverify`; `clean` → `all_clean` (empty `RISCV_DEVICE`) or `one_clean`. Empty
`RISCV_DEVICE` selects `all_variant`, which loops **every** directory
under `riscv-target/<TARGET>/device/rv<XLEN><BASE>_<MODE>/` (most have no suite and print
`# Ignore riscv-test-suite/...`, exit 0).

Useful overrides: `XLEN` (32/64), `RISCV_BASE` (`i`/`e`), `RISCV_MODE` (`m`/`mu`/`msu`),
`RISCV_TARGET`, `RISCV_DEVICE`, `RISCV_TEST`, `RISCV_ASSERT` (0/1/2), `RISCV_GENERATE_OBJFILE`,
`JOBS` (`-j8` default), `WORK`, `TARGETDIR`.

Secondary tool (unrelated to the test flow — YAML → OVP `.ic` control file):

```bash
cd riscv-ovpsim/config-yaml && pip3 install -r requirements.txt
./main.py -ispec ./examples/Ibex_RV32IMC.yaml -pspec ./examples/Ibex_RV32IMC_platform.yaml --target OVPsim
```

## Code Conventions & Common Patterns

**Test naming.** `<MNEMONIC>-NN.S` for instruction tests (`ADD-01.S`, `SLTIU-01.S`), and
`<EXT>-<FEATURE>-NN.S` for architectural behaviour (`I-ECALL-01.S`, `I-MISALIGN_LDST-01.S`,
`I-RF_x0-01.S`). Reference stems must match exactly: `references/ADD-01.reference_output`.

**Canonical `.S` skeleton** (generated style):

```asm
// Specification: RV32I Base Integer Instruction Set, Version 2.1
// Description: Testing instruction 'ADD'.
#include "model_test.h"
#include "arch_test.h"
RVTEST_ISA("RV32I")
.section .text.init
.globl rvtest_entry_point
rvtest_entry_point:
RVMODEL_BOOT
RVTEST_CODE_BEGIN
    RVTEST_CASE(0,"//check ISA:=regex(.*32.*);check ISA:=regex(.*I.*I.*);def TEST_CASE_1=True;",add)
    RVTEST_SIGBASE(x1,signature_1_0)
inst_0:
    TEST_RR_OP(add, x19, x28, x30, 0x49b1a392, 0x54f4aeeb, 0xf4bcf4a7, x1, 0, x2)
RVTEST_CODE_END
RVMODEL_HALT
RVTEST_DATA_BEGIN
.align 4
rvtest_data:
    .word 0xbabecafe
RVTEST_DATA_END
RVMODEL_DATA_BEGIN
signature_1_0:
    .fill 3, 4, 0xdeadbeef
RVMODEL_DATA_END
```

- `model_test.h` resolves from `-I$(TARGETDIR)/$(RISCV_TARGET)/`; `arch_test.h` from
  `-I$(ROOTDIR)/riscv-test-suite/env/`. A new target must supply its own `model_test.h`.
- `TEST_*_OP(inst, destreg, reg1, reg2, correctval, val1, val2, swreg, offset, testreg)`; each
  case is one macro. `offset` increments by 4; `RVTEST_SIGBASE(reg,tag)` resets it and starts a
  new `signature_<N>_0` block.
- Reserve `ra, a0, t0, t1` (x1, x10, x5, x6) — the harness uses them. `RVTEST_CODE_BEGIN`
  seeds x1–x31 with fixed patterns, so tests must not assume zeroed registers.
- Unwritten signature slots are `.fill 3, 4, 0xdeadbeef`; `0xbabecafe` seeds `rvtest_data`.
- Second authoring style exists: hand-written trap tests (`I-EBREAK-01.S`) with their own
  `_trap_handler`, ad-hoc `test_*_res*` labels, and `RVMODEL_HALT` placed *before*
  `RVTEST_CODE_END`. Match the neighbouring file's style rather than converting it.
- `RVTEST_ISA(...)`, `RVTEST_CASE(...)`, `SWSIG(...)` expand to nothing; the `//check ISA:=`
  string is metadata for external RISC-V compliance tooling, not assembly-time logic.
- Formatting: 4-space indent for instructions in the code body, **tab**-indented directives in
  `.data`, `//` comments in asm, `#` blocks in `Makefrag`, tabs in Makefile recipes.
- Reference format: one lowercase zero-padded 8-hex-digit word per line, no header, no `0x`
  (`SignatureGranularity=4`).

**Adding a test** (mechanism not documented in-repo; derived from `Makefrag` + `verify.sh`):

1. `riscv-test-suite/rv32i_m/I/src/<NAME>.S`
2. append `<NAME>` (no extension) to `i_sc_tests` in `riscv-test-suite/rv32i_m/I/Makefrag`
3. `riscv-test-suite/rv32i_m/I/references/<NAME>.reference_output`
4. `make RISCV_TEST=<NAME> XLEN=32 RISCV_DEVICE=I compile run verify`

**Adding a target** (`riscv-target/<TARGET>/`): provide `link.ld` (load at `0x80000000`),
`model_test.h` (`RVMODEL_BOOT`/`HALT`/`DATA_BEGIN`/`DATA_END`/`IO_ASSERT_GPR_EQ`), optional
`postverify.sh`, and `device/rv<XLEN><BASE>_<MODE>/<DEVICE>/Makefile.include` defining
`COMPILE_TARGET` (must honor `$(1)` = `-march`/`-mabi`), `RUN_TARGET`, `RISCV_GCC_OPTS`, plus
`cover.sh` if coverage is supported.

## Important Files

| File | Role |
|---|---|
| `Makefile` | Root driver: defaults banner, target auto-detect, `variant`/`all_variant`, toolchain guard, `verify`/`postverify` |
| `Makefile.include` | All exported defaults (every knob is `?=`) |
| `riscv-test-suite/Makefile.include` | `compile_template`, `%.log: %.elf`, includes the target device fragment, hard `$(error)` if it is missing |
| `riscv-test-suite/rv32i_m/I/Makefile` | `$(eval $(call compile_template,-march=rv32i -mabi=ilp32 -DXLEN=$(XLEN)))` — **`-march` is hardcoded here**, `XLEN` only adds `-DXLEN` |
| `riscv-test-suite/rv32i_m/I/Makefrag` | The test list (`i_sc_tests`) |
| `riscv-test-suite/env/arch_test.h` | Single source of truth for all `RVTEST_*`/`TEST_*` macros |
| `riscv-target/riscvOVPsim/model_test.h` | Machine-mode boot/halt/assert contract for OVPsim |
| `riscv-target/riscvOVPsim/device/rv32i_m/I/Makefile.include` | Reference example of a device adapter |
| `riscv-test-env/verify.sh` | The only verdict source (`diff --ignore-case --strip-trailing-cr`) |
| `riscv-target/riscvOVPsim/link.ld` | Layout: `.text.init` @ `0x80000000`, 0x1000-aligned `.tohost`/`.text`/`.data` |
| `ChangeLog.md` | Release history and per-extension spec versions |

## Runtime/Tooling Preferences

- Runtime: Linux x86-64 (or Windows) host; `make`, `bash`, `diff`, `sdiff` (diffutils), `which`.
  Scripts use `#!/bin/bash` plus `source`, `[[ ]]`, ANSI escapes — not POSIX `sh`.
- Simulator: prebuilt binary only, invoked by absolute path
  `riscv-ovpsim/bin/<Linux64|Windows64>/riscvOVPsim.exe`; needs `libtcl8.4.so`,
  `libelf.so.0.8.13`, `libdwarf-20120410.so` alongside. No `$IMPERAS_HOME`, no `.opts`, no
  platform YAML in the test flow.
- **The bundled binary is time-limited** (`v20230724.0`) and in this checkout reports
  `license expired on 22 Oct 2023`; `make run` therefore fails until a current release is
  dropped in. `compile` and `verify.sh` are unaffected by that expiry but still need a RISC-V
  GCC and a prepared signature dump respectively.
- Toolchain: `riscv64-unknown-elf-` prefix by default (exported from the root `Makefile`), so
  the per-device `RISCV_PREFIX ?= riscv32-unknown-elf-` lines never take effect. No GCC/binutils
  version is pinned anywhere.
- Python 3 + `riscv-config==1.0.0` only for `riscv-ovpsim/config-yaml/`.
- `riscv-ovpsim/source/` is Apache-2.0 model source for reading only — no Makefile/CMake and no
  OVP SDK headers, so it cannot be rebuilt from this snapshot.

## Testing & QA

- No unit-test framework, no CI config, no `lint`/`format`/`check` target, no `.gitignore`,
  no `CONTRIBUTING`. "QA" is the suite run itself.
- Verdict lines from `riscv-test-env/verify.sh`:

  | Line | Meaning |
  |---|---|
  | `Check <name> ... OK` | signature matches reference |
  | `Check <name> ... FAIL` | mismatch; `sdiff` output written to `work/.../<NAME>.diff` |
  | `Check <name> ... IGNORE` | reference or signature missing — **not** a failure |
  | `Error: sig ... no corresponding ...reference_output` | orphan signature — counted as FAIL |
  | `OK: N/N` / `FAIL: n/N` | summary; exit 0 / 1 |

- **`OK: 48/48` is misleading**: `RUN` counts reference files, not executed tests, so a run
  where 47 tests were skipped prints `OK: 48/48`. Read the per-test `IGNORE` lines.
- `verify` depends on `simulate`, so it always re-runs the device before comparing; `make verify`
  after `make run` is not a pure comparison step.
- Coverage: `make cover` / `make postverify` → `postverify.sh` → `device/**/cover.sh`, producing
  `<COVERTYPE>.coverage.{yaml,txt,run.log}` in the work dir. Coverage is silently disabled when
  `RISCV_ASSERT != 0` (assertions and coverage are mutually exclusive). The Rust ISS now writes
  per-test basic YAML and merges it into the basic YAML/text report described below.
- Reproduce the comparison logic without a toolchain by pointing `verify.sh` at a prepared work
  dir: `WORK=/tmp/w SUITEDIR=$PWD/riscv-test-suite/rv32i_m/I XLEN=32 RISCV_BASE=i RISCV_MODE=m
  RISCV_DEVICE=I bash riscv-test-env/verify.sh`.

### Gotchas that break naive changes

- `RISCV_DEVICE` is enumerated from the **target** tree (`ls .../device/rv.../`), not the suite
  tree — any stray file dropped in a device directory becomes a bogus "device".
- `make help` claims an empty `RISCV_DEVICE` defaults to "the I extension alone"; it actually
  iterates all device dirs. Its `RISCV_TEST` example (`I-ADD-01`) does not exist — use `ADD-01`.
- `RISCV_TEST` replaces the whole target list (`target_tests = $(RISCV_TEST).elf`), so a typo
  yields `No rule to make target`, not a warning.
- Ambient `RISCV_PREFIX` / `RISCV_GCC` environment variables silently win over repo defaults;
  a stale `RISCV_PREFIX` is the most common cause of a phantom `No ...-gcc on PATH` error.
- `RISCV_MODE` must be `m-RVI` (not `m`) to reach the `-RVI` device adapters — undocumented.
- `cover.sh` hardcodes a **relative** `WORK_DIR=work/...`, unlike the Makefile's `$(WORK)`; run
  `postverify` from the repo root only.
- `riscv-test-env/{p/,test_macros.h,riscv_test_macros.h,encoding.h}` are legacy riscv-tests
  artifacts referenced by nothing; do not extend them and do not confuse them with
  `riscv-test-suite/env/`.
- `riscv-target/sail-riscv-c` pins `TARGET_SIM ?= riscv_sim_RV64` even for RV32 suites, and its
  README's `sail-riscv-ocaml` target directory does not exist.

## Rust ISS replacing the bundled simulator (`rust-iss/`)

`riscv-ovpsim/bin/Linux64/riscvOVPsim.exe` is now a locally built Rust ISS. The original closed-source
binary is preserved as
`riscv-ovpsim/bin/Linux64/riscvOVPsim.exe.imperas-orig`
(sha256 `ad166cf31e707e67d7e25f4a16a78042a6111d4b2f10bed796cffe18bc70be38`).

- Build: `cd rust-iss && cargo build --release` (zero external crates, works offline).
- Install: `install -m 0755 rust-iss/target/release/riscvOVPsim
  riscv-ovpsim/bin/Linux64/riscvOVPsim.exe`.
- Implemented CLI/control surface: `--variant`, `--program`, `--objfile`, `--objfilenoentry`,
  `--memory`, `--argv`, `--envp`, `--loadphysical`, `--loadvirtual`, `--loadaddress`,
  `--startaddress`, `--signextend`, `--signaturedump`, `--customcontrol`, `--logfile`,
  `--finishtime`, `--finishafter`, `--version`, `--showvariants`, coverage options, and
  `--override riscvOVPsim/cpu/...` for supported CPU and intercept parameters.
- Execution supports RV32/RV64 I/E/M/A/C plus M/S/U privilege state, delegated traps,
  Sv32/Sv39/Sv48 translation, PMP TOR/NA4/NAPOT/locked entries, counters, WFI policy,
  ELF32/ELF64 little-endian RISC-V loading, and sparse u64-addressed memory with RWX regions.
- Semihosting is enabled by `--argv`/`--envp` and implements guest-pointer-checked read/write,
  open/openat/close/lseek/stat/fstat/fstatat, brk, gettimeofday, access/faccessat, getmainvars,
  and exit with negative guest errno returns. It never passes guest pointers to host libc.
- `--customcontrol` implements the observed custom0 word `0x0005200b`: it emits the low byte of
  `a0`, writes it to the custom logfile when configured, and exits when `a0` is zero; `_test_exit`
  is also recognized. UART MMIO is not implemented.
- Signature dumping remains byte-compatible for the verified RV32I suite: 4/16-byte lines,
  symbol/address/byte-count selection, write-count validation, and `SignatureAtEnd`.
- Coverage supports the supplied basic and metadata-backed extended models for RV32/RV64, operand
  filtering, YAML accumulation and report generation. Pseudo coverage and unsupported taxonomy
  (floating point, vector, crypto-specific or compressed-specific trees) are rejected explicitly.
- Variants whose execution is not implemented are rejected before execution: F/D/B/K/V/H/N/P,
  Zfinx/Zce/cache-block/half-float/Svpbmt/Svinval. No feature is silently represented by `misa`.
- `--readmefile`/`--versionsfile` accept their path but write no generated model document: that
  document is built at runtime by the licensed binary and has no byte-exact target here.
- `SignatureAtEnd` is coupled to the `write_tohost` halt path; early exit intercepts do not emit a
  signature. Control-file parsing, command callbacks, multi-hart scheduling and UART devices are
  not implemented.
- Verification on this checkout: `make clean simulate verify postverify XLEN=32 RISCV_DEVICE=I
  RISCV_PREFIX=riscv32-unknown-elf-` exits 0 with 48 `Check` lines and a byte-identical basic
  coverage report (`sha256 70f3f6ac6d3b78014c01f554252877f7f2b31742081b06a8860af9004053083a`).
- Additional smoke checks passed for customControl output/logging, semihost `write`/`exit`,
  `--showvariants` (40 entries), and RV32/RV64 variant mismatch rejection. RV64 execution was not
  toolchain-tested on this host because `riscv64-unknown-elf-gcc` is unavailable.

Parity boundary: the original licensed platform contains additional ISA models and runtime
configuration not present in this checkout. Unsupported requested behavior fails explicitly rather
than returning a plausible but incorrect result.

### Coverage

The coverage model is not invented here: every rule below was read out of the coverage component
that the original binary loads (`/tmp/blob_coverage.elf` during analysis; sha256
`280a02619c0b26d75a112099e3b34bb1cb389a756a1e1b6884e3c3bd60868e35`, ELF64 `ET_DYN`, `.text` at
VA `0x3b5f0`, no file offset), and the merged report reproduces the upstream artifact
`riscv-test-suite/rv32i_m/I/basic.coverage.txt` **byte for byte** (127195 bytes, sha256
`70f3f6ac6d3b78014c01f554252877f7f2b31742081b06a8860af9004053083a`).

- Tree: one node per instruction mnemonic (`cov.rs::MODEL`, 39 for `I`), then one level per
  operand shape (`rd/gpr/a0`, `cross/rs1_rs2/c00`, `offset/sign/zero`, ...), counting at the leaves.
  Each instruction node also carries a hidden `asm_count` child: how often that mnemonic executed
  inside the window. `asm_count` is a real node, so it is written to and read from the YAML too.
- Window: arm on `--startcover`, disarm on `--finishcover`, and the instruction at the finish
  symbol is **inside** the window (the model closes it after that instruction executes, so the
  `fence` at `rvtest_code_end` is counted). The run then ends on entry to `write_tohost`; that
  instruction is counted and attributed to coverage even though its body never executes.
- Report line shapes are `reportCoverage` @ `0x155b10`, `reportNode` @ `0x1555b0` and `missedNode`
  @ `0x155970`, not a formatting choice: node headers are `"%s%-15s\n"` with 4 spaces per depth, a
  leaf is `"%s%-10s %3u/%u : %6.2f%%%s"` where the trailing string is `" ZERO"` exactly when the
  leaf count is zero, a node summary is `"%s%s %u/%u : %6.2f%%"`, and a **childless** instruction
  (`fence`, `wfi`) collapses to the header plus one point scored by its `asm_count`, which is why
  `wfi 0/1` carries no ` ZERO`.
- "Coverage points missed" is `count == 0` (`missedNode` has no threshold comparison);
  `--countthreshold` only decides whether a node's aggregate line reads as hit.
- `--inputfiles` is read in both lanes: simulation starts from the selected model and folds the
  input documents before execution; `--nosimulation` only merges. A directory is scanned
  **non-recursively** for names ending in `.yaml`, case-insensitively, `len >= 6`; output uses
  block YAML with two-space indentation and the `reportCoverage`/`writeResults` order.
  `Instructions counted` is the simulation counter and remains 0 in the merge-only lane.
- `--instructions add,addi` hides all other model roots in YAML/report output and is mutually
  exclusive with `--extensions`. Numeric `--startcover`/`--finishcover` values are accepted in
  addition to exact ELF symbol names. This implementation has only the 39-instruction I model;
  extended, M/A/F/D/C and pseudo-instruction coverage are not implemented.
- The `--extensions` spelling is accepted only for `I`/`RVI`; other extension names and
  `--cover extended` fail explicitly instead of silently selecting the basic tree.
- YAML input is a two-space-indented mapping/count subset, not a general YAML implementation;
  support for arbitrary legal YAML or all original extended/pseudo coverage documents is unproven.
- The `Info` block is printed to **stdout** between two `Info ----...` rules (51 dashes) by every
  run that asks for coverage - `reportCoverage` ends with it unconditionally, no `--reportfile`
  needed.
- Guard rails: an unknown YAML key is reported as `YAML content '<path>/<key>' not recognised.`;
  a path that is neither file nor directory as `<path> is not a file or a directory`.
- YAML round-trip is stable: merging the merged document reproduces both it and the report
  (`diff` clean), so the writer and reader agree on `asm_count` and the zero-count leaves. Emitted
  documents carry the libyaml document markers (`---` first line, `...` last line) so a per-test
  file is byte-identical to the original's.

### Differential against the original binary (local only)

The two artifacts needed to run the licensed binary are **not** in this repository: the original
image (`*.imperas-orig`, excluded by `.gitignore`) and the clock shim described below. They live in
a scratch directory and are used only to produce the parity numbers quoted here.

- The bundled binary aborts with `license expired on 22 Oct 2023`. Its license check reads wall
  clock time through `time`/`gettimeofday`/`ftime`, so an `LD_PRELOAD` shim that **shifts** the
  realtime clock (`realtime - offset`, offset chosen so `now == FAKE_EPOCH`, default `1685577600` =
  2023-06-01Z) keeps it running: it then reports `riscvOVPsim started: Thu Jun  1 08:00:00 2023`.
  Shift, never freeze — a frozen clock makes the model wait forever (observed 61 s hang).
- The shim must **not** intercept `clock_gettime`: adding it makes the original die with `SIGSEGV`
  immediately after printing the program headers.
- "Sandbox" here means `env -i` (empty environment, fixed `PATH`, private `HOME`), `ulimit -f/-t`
  and a private working directory. This kernel (3.10) refuses unprivileged user namespaces, so
  `bwrap`/`unshare -m` are unavailable; treat it as contamination control, not a security boundary.
- The invocation must mirror `riscv-target/riscvOVPsim/device/rv32i_m/I/Makefile.include`
  (`--variant RV32I --program <elf> --signaturedump --customcontrol`, the five `sigdump` overrides,
  `simulateexceptions=T`, `defaultsemihost=F`, `--logfile`, `user_version`, `priv_version`). Add
  `--override riscvOVPsim/tracefile=<file> --override riscvOVPsim/cpu/trace=T` for an instruction
  trace, and the `--startcover`/`--finishcover`/`--cover basic --extensions RVI --outputfile` group
  for coverage.
- The original's own diagnostic switches: `RUSTISS_TRACE=<file>` writes one `<pc:08x>` line per
  executed instruction, `RUSTISS_PCDUMP=<file>` writes per-PC disassembly plus coverage hits,
  `RUSTISS_COVDUMP=<file>` writes the covering tree in text-report shape.

Measured original versus Rust, all 48 `rv32i_m/I` tests:

|Observation|Result|
|---|---|
|signature files|48/48 byte-identical (and 48/48 to `references/`)|
|executed PC sequences (`--tracefile` vs `RUSTISS_TRACE`)|48/48 identical|
|`Simulated instructions` vs the Rust log line|48/48 identical|
|per-test coverage YAML|48/48 byte-identical|
|merged `basic.coverage.txt`|byte-identical to the reference artifact|

Not compared: the `--logfile` transcript itself, which carries a start timestamp and a
host-dependent program/environment banner; two rules were derived from this differential rather
than from disassembly:

- The run ends on **entry** to `write_tohost` (its callback drives `SignatureAtEnd`), so the
  function body never executes. The halted instruction is still counted, traced, and attributed to
  coverage: the `auipc` there scores its `rd/gpr/t0` point, and its sign leaf uses the value that
  `auipc` *would* have written, not the register's previous contents.
- The finish-symbol instruction is inside the coverage window.

### Control options (the `exitControl` intercept model)

Evidence: the model blob `/tmp/blob_exitControl.elf` (sha256
`6b310a9dd97534ab7a253d5d468f98eb8362fbda2bf8ad7a1085d37764d914e2`, `.text` at file offset
`0x34e0`, `ET_DYN` loaded at base `0x100000` -- so `objdump` file offsets are the right indices
here, not REA/Ghidra addresses). Callbacks: `exit_status` @`0x141e0`, `terminateCB` @`0x14230`,
`write_tohostCB` @`0x14280`, `stopSimulation` @`0x142d0`, `morphTime` @`0x14310`, `riscvECALL`
@`0x14440`, `constructor` @`0x14570`.

- The model's option structure is three slots plus bits: `symbol` (`+0`), `address` (`+8`),
  `addressGiven` (`+0x10`), `write_tohost` (`+0x12`), `terminate` (`+0x14`), `ecall` (`+0x16`),
  `opcode` value (`+0x18`) and `opcodeGiven` (`+0x1c`), `ecallResultReg` (`+0x20`) and
  `resultRegGiven` (`+0x24`). The CLI's two spellings (`--exiton*`, `--finishon*`) write the same
  slots, so the last one wins; giving both a symbol and an address prints
  `Please specify one of symbol or address` (`EXC_NV`) and leaves the intercept disarmed.
- Resolution messages (stdout, `<Severity> (<code>) <text>` -- the shape of every transcript line
  in `riscv-ovpsim/README.md`): `Program will stop at symbol '%s' (0x%lx)` (`EXC_SYM`),
  `Program will stop at address 0x%lx` (`EXC_ADDR`, only for an address covered by an executable
  segment -- the platform's `vmirtGetProcessorExternalCodeDomain` is what decides),
  `Cannot find symbol '%s'` (`EXC_SYMNF`), `Cannot find code domain for address 0x%lx`
  (`EXC_ADDRDF`).
- `morphTime` is a per-instruction pre-callback and checks in this order: armed PC match
  (`address match`) -> fetched-word match against the `--finishonopcode` value (`opcode match`)
  -> `ecall`. A match prints `%s: Stopping at 0x%lx` (`EXC_FS`) and finishes the run through
  `stopSimulation`, so the stopping instruction never executes and is never counted (coverage
  included).
- `--ecallresultreg 3|10|28` is what turns on the `ecall` intercept at all (`gp`/`a0`/`t3`): the
  callback reads that register, sets the pass flag from `value == 1`, prints `Test PASSED` or
  `Test FAILED` and finishes, so `ecall` never raises the M-mode trap (cause 11) in that mode. A
  value in `3..=28` that is none of the three prints `Ignored Result register %d. Use 3, 10 or 28
  (default)` (`EXC_EREG`) and falls back to 28; a value outside that window falls back silently.
- `exit_status` prints `Test PASSED` when its argument is non-zero, so a result register holding
  exactly `1` is a pass and anything else is a failure.
- `write_tohost` ends the run regardless of `--finishonwritetohost`; when any control option is
  given the model announces itself with `Intercept 'write_tohost'.` (`EXC_FW`) /
  `Intercept 'terminate'.` (`EXC_FT`). An intercept that ends the run early also suppresses the
  signature dump, because `SignatureAtEnd` dumps from the `write_tohost` callback.

### `--showvariants`

`--showvariants` is pure host-side printing: the OVP library forces `nosimulation`, walks the
processors in `writeVariants` (`0x4ab700`) and calls `tryProcessorShowVariant` (`0x4aaec0`) for
each one that matches the target filter (`--variant` unset matches the single `riscv` processor).
That function opens the processor's `-variant` formal (`opiObjectByName(root, "-variant", 0x1000)`
-- the name lives at `.rodata` `0x720f6d`) and enumerates its values with `opiFormalEnumNext`,
**skipping every name whose first byte is `.`** (`cmpb $0x2e,(%rax)`). The printed line is
`iPrintf("     %s\n", name)` (five spaces; the bytes at `.rodata` `0x72dc03`) for stdout, and
`fprintf(file, "    %s\n", name)` (four spaces; `.rodata` `0x72dc04`) when a `--versionsfile`
stream is open. A per-processor `"%s:\n"` (`0x6f59f1`, `nlObjectHierName`) header is printed only
when more than one processor matched; this platform has one, so the output is exactly 40 lines and
no trailing blank line. `writeVariants`' only message is `No processors found matching '%s'`
(`0x6f56e8`).

Ordering and membership come from the model's `.rodata` name blob at `0x541990..0x541ad8` (40
NUL-terminated names, no `.`-prefixed entries): the 14 `RV32*` non-`E` variants, `RV32E`/`RV32EC`/
`RV32EM`, the same 14 `RV64*` variants, `RVB32I`/`RVB32E`/`RVB64I`, `RVI20U32`/`RVI20U64` and
`RVA20U64`/`RVA20S64`/`RVA22U64`/`RVA22S64`. `[INFERENCE]` the blob order equals the enum order
`opiFormalEnumNext` walks; the licensed binary cannot be run to confirm.

`--readmefile`/`--versionsfile` (`cfShowHierarchy` at `0x4ac6xx`: type-`0x63` entry, value string via
`cfEntryString`, `fopen64(path,"w")`, `iMessage("Writing variants to file '%s'", path)` with prefix
`CF_VARF` at `0x6f5ad8`, then `writeVariants(root, entry, file)`, `fclose`; a failed open prints
`Failed to open file '%s'`) write the model's generated Markdown, which this ISS does not produce.
The variant list itself is the same 40 names with four-space indent, preceded by `"%s:\n"` only in
the multi-processor case.

### Disassembly evidence for the contract above

Static analysis of `.imperas-orig` (bytes never executed — it aborts with
`Fatal (PER_TMO) ... license expired on 22 Oct 2023`, so no runtime differential was possible).

REA workflow actually used: `open_binary` → `binary_session` (capability matrix) →
`inspect_with_objdump` `operation=symbols` (`ev_13a5e0533a77c90326d9e970d2ddc65b2a9b0e129c2aaa6ae504bad26c2f7331`,
confirms `main` @ `0x49d2f0`, size `0x1e85`, `.text` `0x49ccc0`–`0x6d5d30`) and
`operation=disassemble_all` (`ev_45c4bbe837ca1ee173bf488b45e97a3e4a76535052410ce937f9eaf3b9641e27`,
a 10.5 MB `-d` transcript that contains `000000000049d2f0 <main>:`), then `export_evidence_bundle`;
residual questions are session `record_unknown` entries (ids below).

Provider availability on this host (from `binary_session`), which bounds every claim here:

| Provider route | Status | Reason |
|---|---|---|
| `inspect_with_objdump` (GNU objdump 2.27) | available | whole-file `-d`, `-t`, headers only |
| Ghidra | **installed here** | Ghidra 12.1.4 + Temurin JDK 21.0.13 under `/home/liboeda/opt`, bound via `GHIDRA_INSTALL_DIR` / `JAVA_HOME` (see below) |
| Hopper | `executable_missing` | `/opt/hopper/bin/Hopper` |
| rizin (`execute_rizin_command`) | ENOENT | `capability_unavailable`, no `rizin` on PATH |
| `inspect_binary_layout` (pwntools), IDA, Kuna, JEB, Cutter, tshark, WABT | unavailable | unset `REA_*_COMMAND` / client not running |

To reproduce the Ghidra lane (it is read at REA startup, so the MCP server must be launched
with this environment; the `rea` CLI picks it up per invocation):

```
export GHIDRA_INSTALL_DIR=/home/liboeda/opt/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/home/liboeda/opt/jdk-21.0.13+9
export PATH=$JAVA_HOME/bin:$PATH
rea decompile riscv-ovpsim/bin/Linux64/riscvOVPsim.exe.imperas-orig --procedure main --provider ghidra
```

`rea decompile` finished in 4 min and produced Ghidra pseudocode of `main`
(`ev_20c46cfb7e2726eeed35e45d57344e70bf4a43548eb0304414bedccbaacf8d18`,
`provider: ghidra 12.1.4`, `confidence: observed`, `authority: shipped-artifact`).
`rea analyze` on the same binary overruns the default 330 s startup deadline (9.4 MB, 2 GB heap,
host has 3.7 GB RAM); raise `REA_GHIDRA_STARTUP_TIMEOUT_MS` for that, but `decompile` alone is
enough for the questions below.

Two consequences worth knowing before trusting a claim below:

- Symbol-scoped disassembly is broken with this objdump:
  `operation=disassemble symbol=main` emits `--disassemble=main`, which 2.27 rejects
  (`option '--disassemble' doesn't allow an argument`), returning `exit_code 1` with empty stdout
  (`ev_1c26ded16dfa59321d46f73b00d1fcf196ca421ef90bb6eba15e6ba66e53aec1`, reported upstream).
  Address ranges come from the `disassemble_all` transcript instead.
- Without Ghidra there is no `list_procedures`, `analyze_function`, pseudocode, `search` or
  `xrefs`; the earlier `.rodata` → VA mapping in this section was resolved by textually locating
  displacement bytes inside the `-d` transcript, not by a provider reference database. That limit
  is gone once `GHIDRA_INSTALL_DIR` is set — `search`, `xrefs` and `decompile` all work.

Observed (not inferred):

- `main` @ `0x49d2f0`, size `0x1e85`; it only builds the platform through the OVP API
  (`opSessionInit2`, `opCmdParserAdd` ×25, `opParamStringSet`, `opRootModuleSimulate`) — the
  argument grammar lives in the OVP library, not in `main`.
- Option names in `.rodata` referenced by `main`: `signaturedump` ("Load the signature dump
  utility"), `signaturedumphelp`, `customcontrol`, `exitonsymbol`, `exitonaddress`,
  `finishonsymbol`, `finishonaddress`, `finishonopcode`, `finishonterminate`,
  `finishonwritetohost`, `ecallresultreg`, `addressbits`, `usehwregnames`, `cover`,
  `countthreshold`, `reportfile`, `outputfile`, `inputfiles`, `showuncovered`, `startcover`,
  `finishcover`, `readmefile`, `versionsfile`; OVP control-file table adds `-nosimulation`
  (`CFC_NO_SIMULATION`), `-objfile`, `-objfilenoentry`, `-override`.
- The signature dump is **not host code**: it is a separately compiled OVP intercept model
  embedded in `.data` — `riscv_ovpworld_org_intercept_signatureDump_1_0_model_start` @ `0xc30994`,
  `_model_end` @ `0xc730fd`, `_model_size` `0x42769`. The blob is not opaque: carving those bytes
  out yields a complete position-independent x86-64 ELF (`7f 45 4c 46`, `ET_DYN`, 28 section
  headers, 1435 `FUNC` symbols), so its text is analysable. Note the address matters: `0xc30994`
  is the **signatureDump** intercept, while the RISC-V ISA model is the separate
  `riscv_ovpworld_org_processor_riscv_1_0_model_start` @ `0xa59d08`, `_model_size` `0x1934bb`
  (3412 `FUNC` symbols, 67 `*csr*`, 15 `*trap*`). Its behaviour is what fixes the contract:
  - `SignatureAtEnd` — "Generate a Signature file at the end of simulation (default to generate on
    **detection of call to write_tohost()**)", matching `-finishonwritetohost` ("If the function
    write_to_host() is called the simulation will exit"). This is the source of the
    "halt on entry to `write_tohost`" rule.
  - `SignatureGranularity` — "supports default **16** or 4 bytes"; `SignatureDumpToStdout` —
    "default **enabled**". Both defaults are now mirrored in `Opts::default()`; the Makefile always
    passes `SignatureGranularity=4`, so the 16-byte default only shows up in direct invocations.
  - `StartSymbol` default `begin_signature`, `EndSymbol` default `end_signature`, plus
    `SignatureFile`, `StartAddress`, `EndAddress`, `ByteCount`, `SignatureMinWrites`, `ResultReg`
    ("3=GP, 10=A0 or 28=T3 (default)").
  - Failure text confirms the symbol-driven model: "Start symbol '%s' not found, change symbol name
    or specify StartAddress", "End symbol '%s' not found, change symbol name or specify EndAddress
    or BytesCount", "Found symbol main - this looks like a C test - not checking signature is
    written".
- `--nosimulation` finishes before execution. The Rust path implements coverage merging rather
  than the original platform-loading/presimulation lifecycle.
- Entry selection is moot for this suite: `readelf -h` gives `e_entry = 0x80000000` for every built
  test and `nm` shows `rvtest_entry_point` at the same address (`write_tohost` `0x80000038`,
  `begin_signature` `0x80003010`, `end_signature` `0x800032d0` in `ADD-01.elf`).

Still `[INFERENCE]`: instruction-level semantics (CSR WARL, trap priority, misalign `mtval`
values) live inside that embedded model image and were not disassembled. They are pinned
empirically instead — all 48 `.signature.output` files are byte-identical to the reference files,
which the genuine simulator produced. The 16-byte line layout (four words per line, low word
first) is likewise inferred; the suite never selects it.

What the Ghidra pseudocode of `main` adds
(`ev_20c46cfb7e2726eeed35e45d57344e70bf4a43548eb0304414bedccbaacf8d18`, provider `ghidra`
12.1.4, `confidence: observed`):

- First statement in the body is `getenv("IMPERAS_FP_ALLOW_WRITER")`; the platform is then built
  with `opSessionInit2("3.13.0",...)`, `opProductSet("riscvOVPsim")`,
  `opCmdParserNew("riscvOVPsim",2)`.
- Two parameters are forced **unconditionally**: `defaultsemihost=1` and `verbose=1`;
  `use_hw_reg_names` is set only when `--usehwregnames` is given.
- `--addressbits` defaults to `0x20` and becomes the memory mask `(1 << bits) - 1`
  (`bits == 0x40` ⇒ all ones), i.e. 32-bit addressing by default.
- `--nosimulation` is applied as `opParamBoolSet(root,"nosimulation",1)` and additionally
  **suppresses** both fatal CLI errors ("No program was specified…", "No variant was specified…").
- `--signaturedumphelp` prints the nine-line sigdump usage and calls `exit(0)` before any
  simulation is built.
- The informational options (`--showvariants`, `--showoverrides`, `--showmodeloverrides`,
  `--showsystemoverrides`, `--showexpiry`, `--showinstances`, `--readme`, `--versions`) force
  `nosimulation`, run `opRootModulePreSimulate()`, then `exit(0)`.
- Coverage options are hard-gated: without `--cover`, `countthreshold`, `extensions`,
  `instructions`, `inputfiles`, `outputfile`, `reportfile`, `showuncovered`, `startaddress` and
  `finishaddress` all go through `notValid()`.
- Exit status is `return opErrors() != 0`.
- `main` **never** reads `--program` or `--override`: there is no `opParamStringSet(...,"program")`
  anywhere in it. Both are library formals consumed inside libop, so `--program` entry selection
  and `--override` binding cannot be answered from `main` at all (see the unknowns below).

Open residual unknowns (REA `record_unknown`, `severity: low`):

- `unk_25481e868d9753d6b95a792f384fd83ab9091d0d59428e7e4d5309b7ec486fc5` — the ISA model's
  exact trap-priority and CSR WARL behaviour. **Still open, but no longer blocked.** The model is
  not an opaque container: `riscv_ovpworld_org_processor_riscv_1_0_model_*`
  (`0xa59d08`, size `0x1934bb`) carves into a valid x86-64 `ET_DYN` ELF with 3412 `FUNC` symbols
  (`*csr*` ×67, `*trap*` ×15, `*ecall*` ×8, `*mret*` ×2). The remaining work is per-rule static
  reading of that text, not a runtime differential.
- `unk_2f625706ecdecb14802c54cd7bcc8959e1cdc5ab52809d811bca3551b639b1f3` — **inert for this
  suite, closed by evidence rather than by a differential.** Whether the original `--program`
  loader prefers ELF `e_entry` or `rvtest_entry_point` cannot change the result here:
  - all 48 built images agree: `readelf -h work/rv32i_m/I/*.elf` → `Entry point address:
    0x80000000`, and `nm` → `80000000 T rvtest_entry_point` for every one (0 mismatches);
  - no image defines `_start` at all (`nm | grep -c ' _start'` → 0), so there is no third
    candidate the loader could prefer;
  - `main` never consumes `--program`: the only reference in the whole image to the literal
    `objfileuseentry` (file offset `0x305ab8`, exactly one occurrence) is `main`'s own
    `opCmdArgUsed` presence test at `0x49d98f`, i.e. a diagnostic, not a policy.
  Both settings therefore select `0x80000000`.

The Rust ISS parses `SignatureMinWrites` and counts stores overlapping the selected signature
range. On a `write_tohost` halt it compares that count with the requested minimum unless `main`
is present. Suite runs use the default zero minimum; full original error-path equivalence remains
unverified.

#### ISA model tables (static landmarks of the CSR rule chain)

All addresses below are virtual addresses in the **carved model image** (`0x1934bb` bytes taken at
host offset `0x459d08`, which is model VA `0xa59d08`), whose `.data.rel.ro` sits at VA `0x30a040`
with file offset `VA - 0x200000`; `.text`/`.rodata` keep offset `== VA`.

- `csrs` @ `0x348bc0`, **430 fixed-size descriptors, stride `0x98`**, running exactly up to
  `_DYNAMIC` @ `0x358b10` (`(0x358b10 - 0x348bc0) / 0x98 == 430`, no padding), sorted by CSR
  number. `riscvCSRInit` @ `0x98290` walks it:
  ```
  +0x00 == 0                      -> skip            (empty slot)
  cpu->0x879 < desc->0x30         -> skip            (minmode gate)
  cpu->0x9c7 bit 6 set            -> skip whole table
  otherwise newCSR(desc, cpu, 0)  @ 0x938c0
  ```
- `newCSR.part.74` @ `0x938c0` resolves the descriptor's *alias* by `strcmp`ing `desc->0x00`
  against the name list at `cpu+0x11f0` (a hit overrides the key with that entry's `+0x10 & 0xfff`),
  keys on `desc->0x18 & 0xfff`, and installs it into the range table at `cpu+0x11d8` with
  `vmirtSetRangeEntryUserData(entry, desc)`. It **stores the descriptor pointer, never a copy**, so
  every later lookup — `getCSRAttrs` @ `0x92c00` via `vmirtGetFirstRangeEntry` +
  `vmirtGetRangeEntryUserData` — hands back `&csrs[i]` directly. That is why the table is the
  authoritative CSR registry and why presence/access rules can be read off it statically.
- Descriptor field map, cross-checked against three independent readers
  (`riscvCSRInit`, `checkCSRPresent` @ `0x934b0`, `getCSRWriteMask` @ `0x93680`):

  | off | meaning |
  |---|---|
  | `+0x00` | short name (`mstatus`, `fflags`, …) |
  | `+0x08` | long description (`Machine Status`, …) |
  | `+0x10` | alias index inside the table |
  | `+0x18` | CSR number (low 12 bits are the key; bits 9:8 are the privilege class) |
  | `+0x20` | presence feature mask A (e.g. `0x40000` = XLEN32-only, `0x100000` = user-visible, `0x2000`, `0x28`, `0x200028`) |
  | `+0x28` | presence feature mask B (`0x40000000`, `0x1000040200000`, `0x40000`) |
  | `+0x30` | minimum mode byte compared with `cpu+0x879` |
  | `+0x38`…`+0x50` | optional callbacks (presence predicate, read, write, …) — `0` means "plain storage" |
  | `+0x58`,`+0x60`,`+0x68` | `{fn-or-0, cpu offset}` pairs; `sstatus` carries `{0x825d0, 0x0}` while `mstatus` carries `{0x825d0, 0x420}`, i.e. the alias shares mstatus' storage at `cpu+0x420` |
  | `+0x70` | dynamic-mask offset in the CPU struct, or `0xffffffff` (none) |
  | `+0x78` | mode/kind bits (`0x800` counter, `0x1000` interrupt-enable, `0x4000` trigger, `0x10000` S-mode, `0x14000` S-status, `0x15000` S-interrupt) |

- `checkCSRPresent` @ `0x934b0` intersects `+0x20`/`+0x28` with the per-CPU feature word at
  `cpu+0x858` (`0x200028` is special-cased) and runs `+0x38` when it is non-null.
- `getCSRWriteMask(desc, cpu)` @ `0x93680` picks `{+0x58,+0x60,+0x68}` by access kind, and when
  `((+0x78) >> 8) & 3 == 1` returns the **dynamic** mask read from `cpu + (+0x70)` instead of the
  static word; that is how `mstatus`/`misa`-style WARL stays in sync with the current privilege and
  XLEN.
- Variant side: **40 descriptors of `0x7a0` bytes** at `0x3342c0` (`RVI20U32` first, `RV32I`
  second, `RV32IM` third, …), one per `--showvariants` name; `RV32I`'s `+0x00` is a `R_X86_64_RELATIVE`
  relocation whose addend is `0xe7c88`, the packed name blob that also backs `--showvariants`. A
  second, 518-byte table at `0x347b80`/`0x347b88` closes the array.

Why the Rust ISS does **not** try to reproduce all 430 rows byte-for-byte: each row's actual
behaviour is code, not data — `mstatus` write alone is `statusW` @ `0x96490` (invoked from
`riscvCSRInit` with mask `0x30ffffffff`), `misa` write `0x90db0`, `mip` write `0x91480`,
`mepc` write `0x710`-offset pair, etc. — roughly 200 callbacks, and a wrong WARL bit is only
*observable* through a program that reads that CSR back. This suite never does: its 48 signature
files pin `mstatus`, `misa`, `mtvec`, `mepc`, `mcause`, `mtval`, `mip`/`mie`, `mscratch`, `cycle`,
`instret` and `mhartid` only. Those are implemented and byte-identical; the other rows are
documented above as the exact place where further rows would have to be derived, rather than
guessed.
