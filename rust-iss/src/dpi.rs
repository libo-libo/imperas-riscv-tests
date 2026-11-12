//! DPI-C reference model for the CV32E40P step-and-compare testbench.
//!
//! `vendor_lib/rustiss/sv/rustiss_CV32.sv` imports `svimp_entry`/`svimp_exit`
//! and exports the `svexp_*` helpers called from here. Only scalars and
//! `const char *` cross the boundary, so nothing depends on a struct layout
//! shared with the simulator.
//!
//! ## Shape of a run
//!
//! `svimp_entry` loads the ELF image, builds the machine, and then parks inside
//! a loop that never returns. Each turn:
//!
//! 1. `svexp_step()` blocks until the testbench asks the model for one more
//!    instruction. It waits on the RVVI control event, not on a clock edge: the
//!    step-and-compare FSM stops `bus.Clk` while it drives the model.
//! 2. `Machine::step_one` executes exactly one instruction of the image.
//! 3. The new architectural state is published (`svexp_setGPR`, `svexp_setCSR`,
//!    `svexp_setDECODE`) and the step is reported (`svexp_setRESULT`), which is
//!    what wakes the FSM. It compares that state against the instruction RTL
//!    retired first.
//!
//! Traps are reported through the same call with `isvalid = 0`; the wrapper
//! turns an `ecall` trap into a comparable instruction on its own, which is why
//! `decode_string` spells that mnemonic out exactly.
//!
//! ## Deliberate omissions
//!
//! * Interrupts: the DUT's `irq_i` is not visible here (nothing calls
//!   `svimp_io`), so the model never takes an asynchronous trap. A firmware that
//!   enables `mie` and receives an interrupt would desynchronise at the trap.
//! * External bus faults and `haltreq`: same channel, same reason.
//! * The DUT's memory is the OBI agent's `cntxt.mem`, a different array from the
//!   `ram.sv` instance wired to this module. Writes are mirrored into that
//!   instance only because `monitor.sv` dumps its final signature from it.

// This file is the crate root of the `cv32dpi` cdylib target (see `Cargo.toml`),
// a second entry point into the same interpreter as `src/main.rs`.
mod config;
mod cov;
mod cpu;
mod elf;
mod memory;
mod semihost;
mod yaml;

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};

use crate::config::CpuConfig;
use crate::cpu::{Flow, Machine};
use crate::memory::Memory;

//
// DPI contract, matching the exports in rustiss_CV32.sv.
//
extern "C" {
    /// Advance the model by one instruction; blocks until the FSM orders it.
    fn svexp_step();
    /// Back door into the model's RAM image (`ram.memory.mem`, word indexed).
    fn svexp_dmiWrite(address: u32, data: c_int);
    fn svexp_setGPR(index: c_int, value: i64);
    fn svexp_setCSR(name: *const c_char, index: c_int, value: i64);
    fn svexp_setDECODE(value: *const c_char, insn: c_int, width: c_int);
    /// `retpc` is used when `isvalid`, `excpc` otherwise.
    fn svexp_setRESULT(
        isvalid: c_int,
        retpc: i64,
        excpc: i64,
        nextpc: i64,
        order: i64,
        irq_ack: c_int,
        irq_id: c_int,
        dm: c_int,
    );
}

/// CSRs published to the testbench.
///
/// The comparison loop iterates exactly the entries the model pushed and calls
/// `uvm_error` for any name it does not recognise, so this list must stay a
/// subset of `uvmt_cv32e40p_step_compare.sv`'s `case (index)` labels. `mip` is
/// excluded because the DUT side is unconditionally ignored; the counters are
/// excluded because they always differ between two models.
const CSRS: [(&CStr, u32); 11] = [
    (c"mstatus", 0x300),
    (c"misa", 0x301),
    (c"mie", 0x304),
    (c"mtvec", 0x305),
    (c"mcountinhibit", 0x320),
    (c"mscratch", 0x340),
    (c"mepc", 0x341),
    (c"mcause", 0x342),
    (c"mvendorid", 0xf11),
    (c"marchid", 0xf12),
    (c"mhartid", 0xf14),
];

/// DUT reset values (`cv32e40p_cs_registers.sv`) that differ from a zeroed
/// machine: `mstatus.MPP = 3`, `mtvec` mode = vectored, `mcountinhibit` gates
/// `mcycle` and the HPM counters. `misa` is built from the variant; the
/// identification CSRs are the ones this core reports.
const RESET_MSTATUS: u64 = 0x1800;
const RESET_MTVEC: u64 = 0x1;
const RESET_MCOUNTINHIBIT: u64 = 0x9;
const MVENDORID: u64 = 0x602;
const MARCHID: u64 = 4;

struct Lane {
    m: Machine,
    segments: usize,
    steps: u64,
}

thread_local! {
    static LANE: RefCell<Option<Lane>> = const { RefCell::new(None) };
}

struct Step {
    pc: u64,
    insn: u32,
    len: u64,
    retired: bool,
}

fn fatal(message: &str) -> ! {
    eprintln!("[rustiss] {message}");
    std::process::exit(1)
}

/// Owned copy of an incoming SV `string`.
unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn config() -> Result<CpuConfig, String> {
    // The DUT is RV32IMC, always machine mode. `CpuConfig` is shared with the
    // command-line simulator, which reaches S-mode through `--variant`; drop it
    // here instead of teaching every caller about a new variant name.
    let mut cfg = CpuConfig::from_variant("RV32IMC")?;
    cfg.supervisor_mode = false;
    // `misa` is compared instruction by instruction: the DUT reports
    // `0x4000_1104` (MXL=1, I, M, C), so neither U nor S may be advertised.
    cfg.extensions &= !((1u64 << (b'S' - b'A')) | (1u64 << (b'U' - b'A')));
    // `mtvec` write: the core keeps `{wdata[31:8], 6'h0, wdata[0]}` and vectors
    // exceptions to `{mtvec[31:8], 8'h0}`.
    cfg.tvec_align = 8;
    cfg.mtvec = RESET_MTVEC;
    // `_exit` ends in `wfi` with no interrupt source; the core treats it as a
    // hint and the firmware never returns from it.
    cfg.wfi_is_nop = true;
    Ok(cfg)
}

fn build(path: &str) -> Result<Lane, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let image = elf::parse(&bytes).map_err(|e| format!("{path}: {e}"))?;
    if image.xlen != 32 {
        return Err(format!("{path} is RV{}, this model is RV32", image.xlen));
    }
    let mut mem = Memory::new(32);
    for seg in &image.segments {
        mem.zero(seg.vaddr, seg.memsz)?;
        mem.load(seg.vaddr, &seg.data)?;
    }
    // Mirror the image into the simulator's RAM so `monitor.sv` can dump a
    // signature out of it; the model's own copy stays authoritative.
    for seg in &image.segments {
        let mut a = seg.vaddr & !3;
        while a < seg.vaddr + seg.memsz {
            let word = mem.read(a, 4).unwrap_or(0) as u32;
            unsafe { svexp_dmiWrite(a as u32, word as c_int) };
            a += 4;
        }
    }
    mem.mirror = Some(Vec::new());
    let mut m = Machine::new(mem, image.entry, None, config()?);
    m.mstatus = RESET_MSTATUS;
    m.mtvec = RESET_MTVEC;
    m.mcountinhibit = RESET_MCOUNTINHIBIT;
    m.mvendorid = MVENDORID;
    m.marchid = MARCHID;
    Ok(Lane { m, segments: image.segments.len(), steps: 0 })
}

/// Execute one instruction and push the words it stored into the SV-side RAM.
fn advance() -> Step {
    LANE.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let lane = match borrow.as_mut() {
            Some(l) => l,
            None => fatal("step requested before svimp_entry"),
        };
        let report = match lane.m.step_one() {
            Ok(r) => r,
            Err(e) => fatal(&format!("step failed at 0x{:x}: {e}", lane.m.pc)),
        };
        lane.steps += 1;
        let mut dirty = lane.m.mem.mirror.take().unwrap_or_default();
        if !dirty.is_empty() {
            dirty.sort_unstable();
            dirty.dedup();
            for word in dirty.iter() {
                let value = lane.m.mem.read(word << 2, 4).unwrap_or(0) as u32;
                unsafe { svexp_dmiWrite((word << 2) as u32, value as c_int) };
            }
            dirty.clear();
        }
        lane.m.mem.mirror = Some(dirty);
        Step { pc: report.pc, insn: report.insn, len: report.len, retired: matches!(report.flow, Flow::Next) }
    })
}

/// Publish the state after `advance` and wake the comparison FSM.
fn report(step: Step) {
    let mut gpr = [0i64; 32];
    let mut csr = [0i64; CSRS.len()];
    let (pc, next, order, decode) = LANE.with(|cell| {
        let borrow = cell.borrow();
        let lane = borrow.as_ref().expect("lane initialised by advance");
        for i in 0..32 {
            gpr[i] = lane.m.x[i] as i64;
        }
        for (i, (_, address)) in CSRS.iter().enumerate() {
            csr[i] = lane.m.csr_read(*address).unwrap_or(0) as i64;
        }
        (step.pc, lane.m.pc, lane.m.instret, CString::new(lane.m.decode_string(step.insn, step.len)).unwrap_or_default())
    });
    unsafe {
        for (i, value) in gpr.iter().enumerate() {
            svexp_setGPR(i as c_int, *value);
        }
        for (i, (name, address)) in CSRS.iter().enumerate() {
            svexp_setCSR(name.as_ptr(), *address as c_int, csr[i]);
        }
        svexp_setDECODE(decode.as_ptr(), step.insn as c_int, step.len as c_int);
        // A trap is reported at the faulting instruction: the wrapper raises
        // `ovp_cpu_valid` from `state.pc` for the `ecall` case and leaves other
        // traps to resynchronise without a comparison.
        svexp_setRESULT(
            step.retired as c_int,
            pc as i64,
            pc as i64,
            next as i64,
            order as i64,
            0,
            0,
            0,
        );
    }
}

//
// DPI imports from the SV side.
//
/// Load the image and run the model until the simulation ends.
///
/// `+elf_file=` is resolved on the SV side; `variant` is the wrapper's label
/// (`"CV32E40P"`), not an RVVI variant name, and only reaches the log.
#[no_mangle]
pub unsafe extern "C" fn svimp_entry(_cfg: *const c_char, elf_path: *const c_char, variant: *const c_char) {
    let path = unsafe { cstr(elf_path) };
    let label = unsafe { cstr(variant) };
    let lane = match build(&path) {
        Ok(l) => l,
        Err(e) => fatal(&e),
    };
    println!(
        "[rustiss] {label}: entry 0x{:x}, misa 0x{:x}, {} segment(s)",
        lane.m.pc, lane.m.misa, lane.segments
    );
    LANE.with(|cell| *cell.borrow_mut() = Some(lane));
    loop {
        unsafe { svexp_step() };
        report(advance());
    }
}

#[no_mangle]
pub extern "C" fn svimp_exit() {
    let steps = LANE.with(|cell| cell.borrow().as_ref().map(|l| l.steps).unwrap_or(0));
    if steps > 0 {
        println!("[rustiss] stepped {steps} instruction(s)");
    }
}