//! Sparse-memory RV32/RV64 integer interpreter and riscvOVPsim-compatible driver.
//! Integer I/E/M/A/C execution and machine/supervisor/user privileged state are
//! implemented in `cpu`; unsupported ISA extensions fail before execution.

mod cov;
mod elf;
mod logx;
mod yaml;
mod memory;
mod semihost;
mod config;
mod cpu;
use cpu::{Machine, Exit};
use memory::Memory;

use std::fmt::Write as _;
use std::process::ExitCode;


// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

struct Opts {
    variant: Option<String>,
    program: Option<String>,
    signature_dump: bool,
    custom_control: bool,
    custom_logfile: Option<String>,
    logfile: Option<String>,
    sig_file: Option<String>,
    sig_granularity: u32,
    sig_to_stdout: bool,
    sig_min_writes: u32,
    start_symbol: Option<String>,
    end_symbol: Option<String>,
    start_address: Option<u64>,
    end_address: Option<u64>,
    byte_count: Option<u64>,
    ignored_overrides: Vec<String>,
    cover_requested: bool,
    cover_type: Option<String>,
    cover_file: Option<String>,
    cover_inputs: Option<String>,
    cover_report: Option<String>,
    cover_ext: Option<String>,
    cover_start: Option<String>,
    cover_finish: Option<String>,
    count_threshold: u32,
    show_uncovered: bool,
    nosimulation: bool,
    /// `--finishonsymbol` / `--exitonsymbol`: the exitControl model keeps a
    /// single `symbol` parameter, so the two spellings land in one slot (last
    /// one wins) and the *address* variant shares the destination too.
    stop_symbol: Option<String>,
    /// `--finishonaddress` / `--exitonaddress`.
    stop_address: Option<u64>,
    /// `--finishonterminate`: stop when the `terminate` symbol is entered.
    finish_on_terminate: bool,
    /// `--finishonwritetohost`: arms the exitControl write_tohost intercept,
    /// which announces itself once during the platform build.
    finish_on_writetohost: bool,
    /// `--finishonopcode`: stop on the fetched word equal to this value.
    finish_on_opcode: Option<u32>,
    /// `--ecallresultreg` (or `sigdump/ResultReg`). `None` leaves the model's
    /// result-register parameter unset, which suppresses the `Test PASSED` /
    /// `Test FAILED` verdict entirely; `Some(3|10|28)` enables it.
    ecall_result_reg: Option<u32>,
    address_bits: u32,
    /// `--showvariants`: list the processor's `-variant` enum values and exit.
    show_variants: bool,
    /// `--version`: print this Rust implementation's version without loading a program.
    version: bool,
    /// `--finishafter`: stop before the next fetch after this execution-loop count.
    finish_after: Option<u64>,
    /// `--instructions`: comma-separated coverage mnemonic selection.
    cover_instructions: Option<String>,
    argv: Vec<String>, envp: Vec<String>, memories: Vec<String>, objects: Vec<(String,bool)>,
    load_physical: bool, load_address: Option<u64>, entry_address: Option<u64>,
    sign_extend: bool, finish_time: Option<f64>, signature_at_end: bool,
    /// `--trace`: write the per-instruction trace to stdout (or to
    /// `RUSTISS_ITRACE` when that is set).
    trace: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            variant: None,
            program: None,
            signature_dump: false,
            custom_control: false,
            custom_logfile: None,
            logfile: None,
            sig_file: None,
            // The sigdump model falls back to 16-byte lines unless the suite
            // overrides SignatureGranularity; the suite passes 4.
            sig_granularity: 16,
            sig_to_stdout: true,
            sig_min_writes: 0,
            start_symbol: None,
            end_symbol: None,
            start_address: None,
            end_address: None,
            byte_count: None,
            ignored_overrides: Vec::new(),
            cover_requested: false,
            cover_type: None,
            cover_file: None,
            cover_inputs: None,
            cover_report: None,
            cover_ext: None,
            cover_start: None,
            cover_finish: None,
            count_threshold: 1,
            show_uncovered: false,
            nosimulation: false,
            stop_symbol: None,
            stop_address: None,
            finish_on_terminate: false,
            finish_on_writetohost: false,
            finish_on_opcode: None,
            // Unset means the model does not read a result register at all, so
            // it prints no verdict; 3/10/28 select gp/a0/t3.
            ecall_result_reg: None,
            address_bits: 32,
            show_variants: false,
            version: false,
            finish_after: None,
            cover_instructions: None,
            trace: false,
            argv: Vec::new(), envp: Vec::new(), memories: Vec::new(), objects: Vec::new(),
            load_physical: true, load_address: None, entry_address: None, sign_extend: false,
            finish_time: None, signature_at_end: true,
        }
    }
}

fn parse_address(s:&str)->Option<u64>{let t=s.trim();let (neg,t)=t.strip_prefix('-').map_or((false,t),|v|(true,v));let v=if let Some(h)=t.strip_prefix("0x").or_else(||t.strip_prefix("0X")){u64::from_str_radix(h,16).ok()?}else{t.parse().ok()?};Some(if neg{v.wrapping_neg()}else{v})}
fn parse_num(s: &str) -> Option<u32> {
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).ok()?
    } else {
        t.parse::<u32>().ok()?
    };
    Some(if neg { v.wrapping_neg() } else { v })
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut cover_only: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1).peekable();
    fn need<I: Iterator<Item = String>>(
        args: &mut std::iter::Peekable<I>,
        opt: &str,
    ) -> Result<String, String> {
        args.next()
            .ok_or_else(|| format!("option {opt} requires an argument"))
    }
    while let Some(arg) = args.next() {
        let mut value: Option<String> = None;
        let mut name = arg.as_str();
        if let Some(eq) = arg.find('=') {
            if arg.starts_with("--") {
                name = &arg[..eq];
                value = Some(arg[eq + 1..].to_string());
            }
        }
        let mut take = |opt: &str| -> Result<String, String> {
            match value.take() {
                Some(v) => Ok(v),
                None => need(&mut args, opt),
            }
        };
        match name {
            "--version" => o.version = true,
            "--variant" => o.variant = Some(take(name)?),
            "--program" => o.program = Some(take(name)?),
            "--objfile" | "--objfilenoentry" => o.objects.push((take(name)?,name=="--objfile")),
            "--memory" => o.memories.push(take(name)?),
            "--argv" => o.argv.extend(take(name)?.split(',').map(str::to_owned)),
            "--envp" => o.envp.extend(take(name)?.split(',').map(str::to_owned)),
            "--loadphysical" => o.load_physical=if arg.contains('='){parse_bool(&take(name)?)?}else{true},
            "--loadvirtual" => o.load_physical=false,
            "--signextend" => o.sign_extend=if arg.contains('='){parse_bool(&take(name)?)?}else{true},
            "--loadaddress" | "--startaddress" => {let v=take(name)?;let a=parse_address(&v).ok_or_else(||format!("{name}: invalid address '{v}'"))?;if name=="--loadaddress"{o.load_address=Some(a)}else{o.entry_address=Some(a)}},
            "--finishtime" => {let v=take(name)?;let t=v.parse::<f64>().map_err(|_|format!("invalid finish time '{v}'"))?;if !t.is_finite()||t<0.0{return Err("finish time must be finite and nonnegative".into())}o.finish_time=Some(t)},
            "--objfilenoaliases" => return Err("--objfilenoaliases is not implemented; use --objfile or --objfilenoentry".into()),
            "--signaturedump" => o.signature_dump = true,
            "--signaturedumphelp" => {
                println!("Signature dump options are set with --override riscvOVPsim/cpu/sigdump/<name>=<value>");
                println!("  SignatureFile         file to receive the signature");
                println!("  SignatureGranularity  4 or 16 byte lines (default 16)");
                println!("  SignatureDumpToStdout T/F, duplicate the dump on stdout");
                println!("  SignatureMinWrites    minimum writes before the dump is valid");
                println!("  SignatureAtEnd        dump when write_tohost() is called");
                println!("  ResultReg             3=GP, 10=A0 or 28=T3");
                std::process::exit(0);
            }
            "--customcontrol" => o.custom_control = true,
            "--logfile" => o.logfile = Some(take(name)?),
            "--override" => {
                let spec = take(name)?;
                apply_override(&mut o, &spec)?;
            }
            "--cover" => {
                o.cover_requested = true;
                o.cover_type = Some(take(name)?);
            }
            "--countthreshold" | "--outputfile" | "--showuncovered" | "--startcover"
            | "--finishcover" | "--inputfiles" | "--reportfile" | "--extensions"
            | "--instructions" => {
                if name == "--outputfile" {
                    o.cover_file = Some(take(name)?);
                } else if name == "--inputfiles" {
                    o.cover_inputs = Some(take(name)?);
                } else if name == "--reportfile" {
                    o.cover_report = Some(take(name)?);
                } else if name == "--instructions" {
                    o.cover_instructions = Some(take(name)?);
                } else if name == "--extensions" {
                    o.cover_ext = Some(take(name)?);
                } else if name == "--startcover" {
                    o.cover_start = Some(take(name)?);
                } else if name == "--finishcover" {
                    o.cover_finish = Some(take(name)?);
                } else if name == "--countthreshold" {
                    let v = take(name)?;
                    o.count_threshold = parse_num(&v)
                        .ok_or_else(|| format!("{name} '{v}' is not a count"))?;
                } else {
                    o.show_uncovered = true;
                }
                // The original validates this after the whole command line is
                // parsed, so a preceding `--startcover` before `--cover` is
                // accepted (the target Makefile emits exactly that order).
                if !o.cover_requested {
                    cover_only.push(name.to_string());
                }
            }
            "--nosimulation" => o.nosimulation = true,
            // A run already ends on the sigdump model's `write_tohost`
            // callback; this additionally arms exitControl's own intercept,
            // which prints `Intercept 'write_tohost'.` during the build.
            "--finishonwritetohost" => o.finish_on_writetohost = true,
            "--finishafter" => {
                let v = take(name)?;
                o.finish_after = Some(
                    v.trim()
                        .parse::<u64>()
                        .map_err(|_| format!("{name} '{v}' is not an instruction count"))?,
                );
            }
            "--finishonterminate" => o.finish_on_terminate = true,
            "--finishonsymbol" | "--exitonsymbol" => o.stop_symbol = Some(take(name)?),
            "--finishonaddress" | "--exitonaddress" => {
                let v = take(name)?;
                o.stop_address =
                    Some(parse_address(&v).ok_or_else(|| format!("{name} '{v}' is not an address"))?)
            }
            "--finishonopcode" => {
                let v = take(name)?;
                o.finish_on_opcode =
                    Some(parse_num(&v).ok_or_else(|| format!("{name} '{v}' is not an opcode"))?)
            }
            "--ecallresultreg" => {
                let v = take(name)?;
                o.ecall_result_reg = Some(
                    parse_num(&v)
                        .ok_or_else(|| format!("{name} '{v}' is not a register number"))?,
                )
            }
            "--addressbits" => {
                let v = take(name)?;
                o.address_bits = parse_num(&v)
                    .ok_or_else(|| format!("{name} '{v}' is not a bit count"))?;
                if !(1..=64).contains(&o.address_bits){return Err("addressbits must be in 1..=64".into())}
            }
            // `--showvariants` is an information request: the original forces
            // `nosimulation`, lists the processor's `-variant` enum values from
            // `writeVariants`/`tryProcessorShowVariant` and exits 0.
            "--showvariants" => {
                o.show_variants = true;
                o.nosimulation = true;
            }
            // `--readmefile`/`--versionsfile` write the model's generated
            // documentation; they still consume their path argument but no
            // document is produced (see AGENTS.md, known gaps).
            "--readmefile" | "--versionsfile" => {
                let _ = take(name)?;
            }
            "--usehwregnames" => {}
            "--trace" => o.trace = true,
            "--help" | "-h" | "--helpall" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown option '{arg}'")),
        }
    }
    if !o.cover_requested {
        if let Some(name) = cover_only.first() {
            return Err(format!(
                "Option {name} is not valid without -cover to turn on instruction coverage"
            ));
        }
    }
    if o.cover_instructions.is_some() && o.cover_ext.is_some() {
        return Err("Options --extensions and --instructions are mutually exclusive".into());
    }
    Ok(o)
}

fn print_help() {
    println!("riscvOVPsim-style command line (Rust ISS)");
    println!();
    println!("Program selection");
    println!("  --variant <name>            CPU variant, default RV32I; --showvariants lists all");
    println!("  --program <elf>             ELF32/ELF64 program to simulate");
    println!("  --objfile <elf>             extra object, loaded at its own ELF entry point");
    println!("  --objfilenoentry <elf>      extra object, entry point left alone");
    println!("  --loadphysical[=T|F]        load at physical (default) or virtual addresses");
    println!("  --loadvirtual               load at virtual addresses");
    println!("  --loadaddress <addr>        fixed load address for objects that have none");
    println!("  --startaddress <addr>       entry address override");
    println!("  --signextend[=T|F]          sign-extend 32-bit loads");
    println!("  --addressbits <1..64>       addressing width, default 32");
    println!("  --memory <name:lo:hi:perm>  add a region, e.g. ram:0x80000000:0x88000000:rwx");
    println!();
    println!("Runtime control");
    println!("  --finishafter <count>       stop after this many instructions");
    println!("  --finishtime <seconds>      stop after this much simulated time");
    println!("  --finishonsymbol <sym>      stop at a symbol (alias --exitonsymbol)");
    println!("  --finishonaddress <addr>    stop at an address (alias --exitonaddress)");
    println!("  --finishonopcode <word>     stop before a fetched instruction word");
    println!("  --finishonterminate         honour the terminate intercept");
    println!("  --finishonwritetohost       stop on the write_tohost intercept");
    println!("  --ecallresultreg <3|10|28>  pass/fail register used by the ecall intercept");
    println!("  --logfile <file>            write the run transcript here");
    println!();
    println!("Semihosting");
    println!("  --argv <a[,b,...]>          guest argv; implies semihosting");
    println!("  --envp <k=v[,k=v,...]>      guest environment");
    println!("  riscvOVPsim/cpu/defaultsemihost=F turns semihosting off");
    println!();
    println!("Intercept models");
    println!("  --signaturedump             signature dump model");
    println!("  --signaturedumphelp         print the sigdump parameters and exit");
    println!("  --customcontrol             custom0 console output plus console exit");
    println!("  --override <path>=<value>   configure a model or the CPU, see below");
    println!();
    println!("Coverage");
    println!("  --cover <basic|extended>    enable coverage");
    println!("  --extensions <list>         restrict coverage to extension letters");
    println!("  --instructions <list>       restrict coverage to mnemonics");
    println!("  --startcover <sym>          arm the coverage window");
    println!("  --finishcover <sym>         disarm the coverage window");
    println!("  --countthreshold <n>        hit threshold for aggregate lines");
    println!("  --showuncovered             list leaves with zero hits");
    println!("  --outputfile <yaml>         accumulator written after the run");
    println!("  --reportfile <txt>          text report written after the run");
    println!("  --inputfiles <a,b|dir>      inputs for --nosimulation");
    println!("  --nosimulation              merge --inputfiles without executing");
    println!();
    println!("Information");
    println!("  --version                   print the Rust ISS version");
    println!("  --showvariants              list the processor variants and exit");
    println!("  --readmefile <path>         consumes the path; no document is generated");
    println!("  --versionsfile <path>       consumes the path; no document is generated");
    println!("  --usehwregnames             accepted, no effect");
    println!("  --trace                     print an instruction trace to stdout");
    println!("                              (or to RUSTISS_ITRACE=<file> when set)");
    println!();
    println!("Overrides, riscvOVPsim/cpu/<path>=<value>");
    println!("  sigdump/SignatureFile, SignatureGranularity, SignatureDumpToStdout,");
    println!("          SignatureAtEnd, SignatureMinWrites, ResultReg, StartSymbol,");
    println!("          EndSymbol, StartAddress, EndAddress, ByteCount");
    println!("  customcontrol/logfile");
    println!("  cpu/variant, reset_address, mtvec, mtvec_mask, mtvec_is_ro, tvec_align,");
    println!("      unaligned, Zam, unalignedV, wfi_is_nop, wfi_resume_not_trap, mips,");
    println!("      mtime_Hz, PMP_registers, PMP_grain, PMP_undefined, counteren_mask,");
    println!("      scounteren_zero_mask, hcounteren_zero_mask, noinhibit_mask,");
    println!("      cycle_undefined, mcycle_undefined, time_undefined,");
    println!("      instret_undefined, minstret_undefined, hpmcounter_undefined,");
    println!("      mhpmcounter_undefined, misa_MXL, misa_Extensions, add_Extensions,");
    println!("      sub_Extensions, user_version, priv_version, defaultsemihost,");
    println!("      simulateexceptions");
    println!("  Any other CPU override name is an error, not a silent no-op.");
    println!();
    println!("F, D, B, K, V, H, N and P are rejected rather than approximated.");
}

/// The processor's `-variant` enum, in the order the model registers it: the
/// `.rodata` name blob at `0x541990..0x541ad8` of the original image, mirrored
/// here verbatim. `tryProcessorShowVariant` (`0x4aaec0`) walks the formal
/// `-variant` (`0x720f6d`), skips any name whose first byte is `.`, and prints
/// the rest with `iPrintf("     %s\n", name)` to stdout (or with four leading
/// spaces via `fprintf` when a `--versionsfile` stream is open). The list is
/// only reachable when a single processor exists, which is the case for this
/// platform, so no `%s:\n` per-processor header is emitted.
const VARIANTS: [&str; 40] = [
    "RV32I", "RV32IM", "RV32IMC", "RV32IMCZce", "RV32IMAC", "RV32G", "RV32GC", "RV32GCZfinx",
    "RV32GCB", "RV32GCH", "RV32GCK", "RV32GCN", "RV32GCP", "RV32GCV", "RV32E", "RV32EC", "RV32EM",
    "RV64I", "RV64IM", "RV64IMC", "RV64IMCZce", "RV64IMAC", "RV64G", "RV64GC", "RV64GCZfinx",
    "RV64GCB", "RV64GCH", "RV64GCK", "RV64GCN", "RV64GCP", "RV64GCV", "RVB32I", "RVB32E", "RVB64I",
    "RVI20U32", "RVI20U64", "RVA20U64", "RVA20S64", "RVA22U64", "RVA22S64",
];

fn show_variants() {
    for name in VARIANTS {
        println!("     {name}");
    }
}

fn apply_override(o: &mut Opts, spec: &str) -> Result<(), String> {
    let Some((path, value)) = spec.split_once('=') else {
        return Err(format!("override '{spec}' is not <path>=<value>"));
    };
    // Normalise `riscvOVPsim/cpu/<...>`; anything we do not model is inert.
    let tail = path
        .strip_prefix("riscvOVPsim/cpu/")
        .or_else(|| path.strip_prefix("riscvOVPsim/"))
        .unwrap_or(path);
    let lower = tail.to_ascii_lowercase();
    match lower.as_str() {
        "customcontrol/logfile" => o.custom_logfile=Some(value.to_owned()),
        "sigdump/signaturefile" => o.sig_file = Some(value.to_string()),
        "sigdump/signaturegranularity" => {
            o.sig_granularity = parse_num(value)
                .ok_or_else(|| format!("SignatureGranularity '{value}' is not a number"))?
        }
        "sigdump/signaturedumptostdout" => o.sig_to_stdout = is_true(value),
        "sigdump/signatureatend" => o.signature_at_end = match value.to_ascii_lowercase().as_str(){"t"|"true"|"1"=>true,"f"|"false"|"0"=>false,_=>return Err(format!("invalid SignatureAtEnd '{value}'"))},
        "sigdump/signatureminwrites" => {
            o.sig_min_writes = parse_num(value)
                .ok_or_else(|| format!("SignatureMinWrites '{value}' is not a number"))?
        }
        "sigdump/resultreg" => {
            o.ecall_result_reg = Some(
                parse_num(value).ok_or_else(|| format!("ResultReg '{value}' is not a number"))?,
            )
        }
        "sigdump/startsymbol" => o.start_symbol = Some(value.to_string()),
        "sigdump/endsymbol" => o.end_symbol = Some(value.to_string()),
        "sigdump/startaddress" => {
            o.start_address =
                Some(parse_address(value).ok_or_else(|| format!("StartAddress '{value}'"))?)
        }
        "sigdump/endaddress" => {
            o.end_address = Some(parse_address(value).ok_or_else(|| format!("EndAddress '{value}'"))?)
        }
        "sigdump/bytecount" => {
            o.byte_count = Some(parse_address(value).ok_or_else(|| format!("ByteCount '{value}'"))?)
        }
        _ => o.ignored_overrides.push(spec.to_string()),
    }
    Ok(())
}

fn parse_bool(s:&str)->Result<bool,String>{match s.to_ascii_lowercase().as_str(){"t"|"true"|"1"|"yes"=>Ok(true),"f"|"false"|"0"|"no"=>Ok(false),_=>Err(format!("invalid boolean '{s}'"))}}
fn is_true(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "t" | "true" | "1" | "y" | "yes")
}

// ---------------------------------------------------------------------------
// Machine
// ---------------------------------------------------------------------------


/// The platform transcript.
///
/// stdout receives `body` verbatim, chunk by chunk as it is produced (that is
/// what the original does, and it keeps a `customControl` console byte in its
/// place in the stream). `--logfile` receives the session header, the same
/// body, and the `Info Session ended` footer, written when the run finishes.
struct Transcript {
    header: String,
    body: Vec<u8>,
}

impl Transcript {
    fn new(stamp: &str) -> Transcript {
        // The header echoes the command line as given, so the flag column is
        // the process's own argv with `argv[0]` on the `Info PROGRAM` line.
        let mut argv = std::env::args();
        let exe = argv.next().unwrap_or_default();
        let rest: Vec<String> = argv.collect();
        Transcript {
            header: logx::header(&exe, stamp, &rest),
            body: Vec::new(),
        }
    }

    fn raw(&mut self, text: &str) {
        self.body.extend_from_slice(text.as_bytes());
        print!("{text}");
    }

    /// Raw interleaved bytes (`customControl` console output).
    fn bytes(&mut self, b: &[u8]) {
        use std::io::Write as _;
        if b.is_empty() {
            return;
        }
        self.body.extend_from_slice(b);
        let out = std::io::stdout();
        let mut lock = out.lock();
        let _ = lock.write_all(b);
        let _ = lock.flush();
    }

    /// `<Severity> (<code>) <text>`, the shape of every `vmiMessage` line in
    /// `riscv-ovpsim/README.md`.
    fn msg(&mut self, sev: char, code: &str, text: &str) {
        let line = logx::line(sev, code, text);
        self.raw(&line);
    }

    /// Write the `--logfile` document: header, body, footer.
    fn publish(&self, o: &Opts, stamp: &str) -> Result<(), String> {
        let Some(path) = &o.logfile else { return Ok(()) };
        let mut doc = Vec::with_capacity(self.header.len() + self.body.len() + 128);
        doc.extend_from_slice(self.header.as_bytes());
        doc.extend_from_slice(&self.body);
        doc.extend_from_slice(logx::session_ended(stamp).as_bytes());
        std::fs::write(path, doc).map_err(|e| format!("cannot write logfile '{path}': {e}"))
    }
}


// ---------------------------------------------------------------------------
// Program loading
// ---------------------------------------------------------------------------

fn load_program(bytes: &[u8], o: &Opts) -> Result<(elf::Elf, Memory), String> {
    let mut mem = Memory::new(o.address_bits);
    for region in &o.memories { mem.configure(region)?; }
    let mut image = elf::parse(bytes)?;
    fn install(image: &mut elf::Elf, mem: &mut Memory, o: &Opts) -> Result<(), String> {
        let base=image.segments.iter().map(|s|if o.load_physical{s.addr}else{s.vaddr}).min().unwrap_or(0);
        let xlen=image.xlen;
        let convert=|a:u64|->Result<u64,String>{let a=if let Some(dest)=o.load_address {a.checked_sub(base).and_then(|off|dest.checked_add(off)).ok_or("load address overflow")?}else{a};Ok(if o.sign_extend&&xlen==32{a as u32 as i32 as i64 as u64}else{a})};
        for s in &mut image.segments { let a=convert(if o.load_physical{s.addr}else{s.vaddr})?; mem.zero(a,s.memsz)?;mem.load(a,&s.data)?;s.addr=a; }
        image.entry=convert(image.entry)?;
        for (_,a) in &mut image.symbols {*a=convert(*a)?;}
        Ok(())
    }
    install(&mut image,&mut mem,o)?;
    for (index,(path,set_entry)) in o.objects.iter().enumerate() {
        if index==0&&o.program.is_none(){continue}
        let bytes=std::fs::read(path).map_err(|e|format!("cannot read '{path}': {e}"))?;
        let mut extra=elf::parse(&bytes)?;if extra.xlen!=image.xlen{return Err("mixed ELF32/ELF64 objects".into())}
        install(&mut extra,&mut mem,o)?;if *set_entry{image.entry=extra.entry;}image.segments.extend(extra.segments);image.symbols.extend(extra.symbols);
    }
    if let Some(entry)=o.entry_address{image.entry=entry;}
    Ok((image,mem))
}

/// Read and load one program, reporting the platform's own diagnostics for the
/// two failures it can see: a file that cannot be opened and bytes that are not
/// an ELF. A parse failure of a secondary `--objfile` is reported against the
/// primary path, which is the only name the caller supplies.
fn open_program(
    path: &str,
    o: &Opts,
    t: &mut Transcript,
) -> Result<(elf::Elf, Memory), ()> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                t.msg('E', "OR_FNF", &format!("File '{path}' was not found."));
            } else {
                t.msg('E', "OR_FOF", &format!("Failed to open file {path}"));
                t.msg('E', "OR_INV", &format!("File '{path}' was not recognised as one of these formats: ELF"));
            }
            return Err(());
        }
    };
    load_program(&bytes, o).map_err(|_| {
        t.msg('E', "OR_INV", &format!("File '{path}' was not recognised as one of these formats: ELF"));
    })
}

fn symbol(image: &elf::Elf, name: &str) -> Option<u64> {
    image
        .symbols
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| *v)
}

// ---------------------------------------------------------------------------
// Signature dump
// ---------------------------------------------------------------------------

/// Signature-dump parameters resolved exactly as the OVP sigdump intercept
/// model reports them in its `constructor` (evidence
/// `ev_18bb3b1c0403e75a7752d9fe5e0d51c0d58a492e6f5621a86aae497c6e1747b2`).
///
/// Every message below is measured against the shipped image, including the
/// two failure shapes' double space after the code:
///
/// * nothing at all is generated unless `SignatureFile` names a file -- the
///   model's dump routine is entirely inside `if (state->file)`, so a missing
///   `SignatureFile` also suppresses the `SignatureDumpToStdout` copy;
/// * `StartAddress` wins over `StartSymbol`; only a symbol that is actually
///   consulted is announced (`FSB`/`FSE`), and the symbol lines (`SB`/`SE`)
///   that follow are likewise per-symbol. An explicit address path therefore
///   prints no symbol line at all;
/// * `EndAddress` wins over `EndSymbol`, and `ByteCount` is inert here: the
///   size is always the start/end difference. Its only other effect is the
///   parameter's minimum-16 check (`OP_ULT`), which fails the platform build;
/// * a negative size (end above start) is *not* rejected here: it flows into
///   the write-callback range and fails as `MEM_HGM`, which aborts the
///   platform build;
/// * granularity must be 4 or 16, otherwise it falls back to 16 (`SFG`);
/// * the size is snapped with the model's literal arithmetic
///   `(n + 1 - g) & ~g`, applied only when `n % g != 0`. That yields 0 and
///   negative results for small sizes (`sb_3` reduces 3 to 0, `sb_1` reduces 1
///   to -6), so the snapshot is signed;
/// * a failure prints `CF` (configuration failed, dump disabled) and then the
///   specific reason, and is not fatal: the run continues without a dump.
struct SigPlan {
    start: u64,
    bytes: u64,
    gran: u32,
    min_writes: u32,
}

fn plan_signature(image: &elf::Elf, o: &Opts, t: &mut Transcript) -> Result<Option<SigPlan>, String> {
    if o.sig_file.is_none() {
        return Ok(None);
    }
    let start_name = o.start_symbol.as_deref().unwrap_or("begin_signature");
    let end_name = o.end_symbol.as_deref().unwrap_or("end_signature");
    let mut used_end_symbol = false;
    let start = match o.start_address {
        Some(a) => a,
        None => match symbol(image, start_name) {
            Some(v) => {
                t.msg('I', "SIGNATURE_DUMP_FSB", &format!("Found Symbol '{start_name}' in application at 0x{v:x}"));
                v
            }
            None => {
                t.msg('W', "SIGNATURE_DUMP_CF", "Signature File configuration failed - disabled");
                t.msg('W', "SIGNATURE_DUMP_SNF", &format!(" Start symbol '{start_name}' not found, change symbol name or specify StartAddress"));
                return Ok(None);
            }
        },
    };
    let size = match o.end_address {
        Some(a) => (a as i64).wrapping_sub(start as i64),
        None => match symbol(image, end_name) {
            Some(v) => {
                used_end_symbol = true;
                t.msg('I', "SIGNATURE_DUMP_FSE", &format!("Found Symbol '{end_name}' in application at 0x{v:x}"));
                (v as i64).wrapping_sub(start as i64)
            }
            None => {
                t.msg('W', "SIGNATURE_DUMP_CF", "Signature File configuration failed - disabled");
                t.msg('W', "SIGNATURE_DUMP_ENF", &format!(" End symbol '{end_name}' not found, change symbol name or specify EndAddress or BytesCount"));
                return Ok(None);
            }
        },
    };
    let mut gran = o.sig_granularity;
    if gran != 4 && gran != 16 {
        t.msg('W', "SIGNATURE_DUMP_SFG", &format!("Signature File Granularity {gran} not valid. May be 4 or 16 byte blocks. Setting to default 16 bytes"));
        gran = 16;
    }
    let size = if size % i64::from(gran) != 0 {
        let snapped = size.wrapping_add(1).wrapping_sub(i64::from(gran)) & !i64::from(gran);
        t.msg('W', "SIGNATURE_DUMP_SBB", &format!("Signature File format must be granularity byte blocks, reducing signature size {size} to {snapped} bytes"));
        snapped
    } else {
        size
    };
    if size == 0 {
        t.msg('W', "SIGNATURE_DUMP_CF", "Signature File configuration failed - disabled");
        t.msg('W', "SIGNATURE_DUMP_SZ", " Size is zero");
        return Ok(None);
    }
    let file = o.sig_file.as_deref().unwrap_or("");
    t.msg('I', "SIGNATURE_DUMP_EN", &format!("Signature File enabled, file '{file}'."));
    t.msg('I', "SIGNATURE_DUMP_ES", &format!("Extracting signature from 0x{start:x} size {size} bytes"));
    if o.start_address.is_none() {
        t.msg('I', "SIGNATURE_DUMP_SB", &format!("Symbol '{start_name}' at 0x{start:x}"));
    }
    if used_end_symbol {
        // The end symbol's own address, not the start: the message restates the
        // resolved symbol rather than the computed range.
        if let Some(v) = symbol(image, end_name) {
            t.msg('I', "SIGNATURE_DUMP_SE", &format!("Symbol '{end_name}' at 0x{v:x}"));
        }
    }
    if size < 0 {
        // The model passes the signed size into the write callback, whose range
        // check reports `(uint32_t)(size - 1)` zero-extended onto the start.
        let upper = start.wrapping_add(((size - 1) as u32) as u64);
        t.msg('E', "MEM_HGM", &format!("vmirtAddWriteCallback : address range 0x{start:x}:0x{upper:x} outside allowed range 0x0:0xffffffff"));
        return Err(String::new());
    }
    Ok(Some(SigPlan {
        start,
        bytes: size as u64,
        gran,
        min_writes: o.sig_min_writes,
    }))
}

/// Word order inside a line is the model's, not memory order: `signature`
/// walks its index from `granularity - 4` down to 0 and prints each word with
/// `%08x` and no separator, so a 16-byte line shows its highest-addressed word
/// first (evidence
/// `ev_c0b02cd12fb11cd41da37d0dbcd70f2c3bbf8934a8641b171048ef759766183d`).
fn emit_signature(p: &SigPlan, mem: &Memory) -> Result<String, String> {
    let word = |addr: u64| -> Result<u64, String> {
        mem.read(addr,4).ok_or_else(||format!("signature address 0x{addr:x} outside readable memory"))
    };
    let mut out = String::new();
    let mut line = 0u64;
    while line < p.bytes {
        let mut k = p.gran;
        while k >= 4 {
            k -= 4;
            let _ = write!(
                out,
                "{:08x}",
                word(p.start.wrapping_add(line).wrapping_add(u64::from(k)))?
            );
        }
        out.push('\n');
        line = line.wrapping_add(u64::from(p.gran));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// `writeResults` (0x159e80) tail: the coverage document, then the text report,
/// then the `Info` block, which `reportCoverage` (0x155b10) always prints to
/// stdout between two rule lines - with or without any output file.
fn coverage_outputs(
    o: &Opts,
    cov: &cov::Cov,
    counted: u64,
    t: &mut Transcript,
) -> Result<(), String> {
    let ext = o.cover_ext.as_deref();
    if let Some(path) = &o.cover_file {
        t.msg('I', "ICV_WCF", &format!("Writing coverage file {path}"));
        std::fs::write(path, cov.to_yaml())
            .map_err(|e| format!("Failed to write YAML file '{path}': {e}"))?;
        t.msg('I', "ICV_FIN", "Instruction Coverage finished");
    }
    if let Some(path) = &o.cover_report {
        t.msg('I', "ICV_WCR", &format!("Writing coverage report {path}"));
        let body = cov.write_report(ext, o.count_threshold, o.show_uncovered, counted);
        std::fs::write(path, body).map_err(|e| format!("Failed to write report file {path}: {e}"))?;
    }
    t.raw(&format!(
        "{r}\n{}{r}\n",
        cov.info_block(ext, o.count_threshold, counted),
        r = logx::RULE
    ));
    Ok(())
}

/// One `yamlReadFile` (0x155000) input: read the document, fold it into `cov`
/// and report the keys the model's tree does not know (`ICV_YNNF`).
fn read_coverage_file(
    path: &str,
    cov: &mut cov::Cov,
    t: &mut Transcript,
    errors: &mut u32,
) -> Result<(), String> {
    t.msg('I', "ICV_RD", &format!("Reading file {path}"));
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => {
            t.msg('E', "ICV_IVF", &format!("{path} is not a file or a directory"));
            return Ok(());
        }
    };
    match yaml::parse(&text) {
        Ok(doc) => {
            for key in cov.merge_yaml(&doc) {
                t.msg('E', "ICV_YNNF", &format!("YAML content '{key}' not recognised."));
                *errors += 1;
            }
        }
        Err(_) => {
            // `ICV_YIC` is one fixed sentence: the reader only reports that the
            // root is not a mapping, never the libyaml diagnostic behind it.
            t.msg(
                'E',
                "ICV_YIC",
                &format!(
                    "File '{path}' does not have the expected YAML format. Root node is not a mapping"
                ),
            );
            *errors += 1;
        }
    }
    Ok(())
}

/// `readDir` (0x158f90): every readable regular file whose name ends in
/// `.yaml` (case-insensitive, at least six characters) is merged; other entries,
/// subdirectories included, are skipped.
fn read_coverage_dir(
    path: &str,
    cov: &mut cov::Cov,
    t: &mut Transcript,
    errors: &mut u32,
) -> Result<(), String> {
    let entries = std::fs::read_dir(path).map_err(|e| format!("Failed to open directory {path}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory {path}: {e}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let child = format!("{path}/{name}");
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_file || name.len() < 5 || !child[child.len() - 5..].eq_ignore_ascii_case(".yaml") {
            continue;
        }
        read_coverage_file(&child, cov, t, errors)?;
    }
    Ok(())
}

/// `--inputfiles`: each comma-separated entry is a document or a directory to
/// scan. `yamlReadFile` reports a path that exists as neither with `ICV_IVF`
/// and carries on; a document it cannot parse or a key the tree does not know
/// aborts the merge with `ICV_YINC` once every input has been offered.
fn read_coverage_inputs(o: &Opts, cov: &mut cov::Cov, t: &mut Transcript) -> Result<(), String> {
    let mut errors = 0;
    if let Some(inputs) = &o.cover_inputs {
        for path in inputs.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match std::fs::metadata(path) {
                Ok(md) if md.is_file() => read_coverage_file(path, cov, t, &mut errors)?,
                Ok(md) if md.is_dir() => read_coverage_dir(path, cov, t, &mut errors)?,
                _ => t.msg('E', "ICV_IVF", &format!("{path} is not a file or a directory")),
            }
        }
    }
    if errors != 0 {
        return Err(String::new());
    }
    Ok(())
}

/// `ICV_YINC`: the merge is abandoned, the transcript gets one `Fatal` line and
/// the whole run exits non-zero - no coverage document and no report are written.
fn coverage_abort(o: &Opts, t: &mut Transcript, stamp: &str) -> Result<(), String> {
    t.msg('F', "ICV_YINC", "Either the cover specification is incorrect, the wrong model has been selected or the version of the saved coverage data file does not match the software");
    t.raw("Info Exiting\n");
    t.publish(o, stamp)?;
    Err(String::new())
}

/// Bind every `--override riscvOVPsim/cpu/<name>=<value>` to the CPU config.
/// A name the model does not have is *not* a CLI error: the platform build
/// reports it (`CF_UE`) after the loader has printed the program headers, so
/// the specs are returned for the transcript instead of failing here.
fn apply_overrides(config: &mut config::CpuConfig, o: &Opts) -> Result<Vec<String>, String> {
    let mut unknown = Vec::new();
    for spec in &o.ignored_overrides {
        let (path, value) = spec.split_once('=').ok_or("invalid CPU override")?;
        let name = path
            .strip_prefix("riscvOVPsim/cpu/")
            .or_else(|| path.strip_prefix("riscvOVPsim/"))
            .unwrap_or(path);
        match config.apply_override(name, value) {
            Ok(()) => {}
            Err(e) if e.starts_with("unsupported CPU override") => unknown.push(spec.clone()),
            Err(e) => return Err(e),
        }
    }
    Ok(unknown)
}

/// `OP_FIP`: the platform never builds. The original prints one `CF_UE` per
/// unmatched override, then gives up - no statistics, no signature, no
/// shutdown banner, only `Info Session ended` from the session layer.
fn platform_failed(
    o: &Opts,
    t: &mut Transcript,
    stamp: &str,
    unknown: &[String],
) -> Result<(), String> {
    for spec in unknown {
        t.msg(
            'E',
            "CF_UE",
            &format!("'--override {spec}' did not match anything in the platform"),
        );
    }
    t.msg('E', "OP_FIP", "Failed to build platform 'riscvOVPsim'");
    t.publish(o, stamp)?;
    Err(String::new())
}

/// `--nosimulation`: no processor is created and no instruction is simulated.
/// The run still announces the CPU model, prints the time statistics and the
/// shutdown banner, and only *then* merges the `--inputfiles` coverage
/// documents into the `--outputfile` document and the `--reportfile` text.
/// This lane's `Info` block header carries no trailing space.
fn report_coverage(
    o: &Opts,
    t: &mut Transcript,
    stamp: &str,
    started: std::time::Instant,
) -> Result<(), String> {
    let mut config = config::CpuConfig::from_variant(o.variant.as_deref().unwrap_or("RV32I"))?;
    let unknown = apply_overrides(&mut config, o)?;
    if !unknown.is_empty() {
        return platform_failed(o, t, stamp, &unknown);
    }
    // A merge-only run still reads the object file the platform was told
    // about: the header block lands before the coverage parameter lines, and a
    // file that cannot be loaded stops the build after `OP_NOS`.
    if let Some(program) = o.program.as_deref().or_else(|| o.objects.first().map(|p| p.0.as_str())) {
        match open_program(program, o, t) {
            Ok((image, _)) => t.raw(&logx::program(program, &image)),
            Err(()) => {
                t.msg('I', "OP_NOS", "Simulator finishing because 'nosimulation' was specified");
                return platform_failed(o, t, stamp, &[]);
            }
        }
    }
    if o.cover_requested {
        t.msg(
            'I',
            "ICV_PVSN",
            &format!("parameter 'user_version' is '{}'", config.user_version),
        );
        t.msg('I', "ICV_ALI", "Pseudo instructions will be translated");
    }
    t.msg(
        'I',
        "OP_NOS",
        "Simulator finishing because 'nosimulation' was specified",
    );
    let (user, system) = logx::cpu_times();
    t.raw(&logx::time_stats(
        0,
        config.mips as u64,
        user,
        system,
        started.elapsed().as_secs_f64(),
    ));
    t.raw(&logx::shutdown(stamp));
    if o.cover_requested {
        let mut cov = cov::Cov::configured(
            o.cover_type.as_deref().unwrap_or("basic"),
            o.cover_ext.as_deref(),
            o.cover_instructions.as_deref(),
            config.xlen,
        )?;
        if read_coverage_inputs(o, &mut cov, t).is_err() {
            return coverage_abort(o, t, stamp);
        }
        coverage_outputs(o, &cov, 0, t)?;
    }
    t.publish(o, stamp)
}

fn run(o: &Opts) -> Result<(), String> {
    if o.version {
        println!("riscvOVPsim (Rust ISS {})", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if o.show_variants {
        show_variants();
        return Ok(());
    }
    let variant = o.variant.as_deref().unwrap_or("RV32I");
    let mut config = config::CpuConfig::from_variant(variant)?;
    let unknown_overrides = apply_overrides(&mut config, o)?;

    // Every transcript opens with the session header and the product banner,
    // before anything is loaded or configured.
    let stamp = logx::timestamp();
    let started = std::time::Instant::now();
    let mut t = Transcript::new(&stamp);
    t.raw(&logx::banner(&stamp));
    if o.variant.is_none() {
        t.msg('I', "RISCV_ANS1", "Attribute 'variant' not specified; defaulting to 'RV32I'");
    }
    // A merge-only run never builds a platform: no program is needed and no
    // ISA has to be executable, so the requirement comes after this branch.
    if o.nosimulation {
        return report_coverage(o, &mut t, &stamp, started);
    }

    let program = o.program.as_deref().or_else(||o.objects.first().map(|p|p.0.as_str())).ok_or("no --program or --objfile given")?;
    let unsupported=config.extensions & ![b'I',b'E',b'M',b'A',b'C',b'S',b'U'].iter().fold(0u64,|v,c|v|(1u64<<(*c-b'A')));
    if unsupported!=0||config.zfinx{return Err(format!("variant {variant} requests extensions without execution support (ISA mask 0x{unsupported:x}, Zfinx={}); supported execution is RV32/RV64 I/E/M/A/C/S/U",config.zfinx))}
    if config.zcea||config.zceb||config.zcee||config.zicbom||config.zicboz||config.zicbop||config.zfhmin||config.svpbmt||config.svinval{return Err("requested Zce/cache-block/half-float/Svpbmt/Svinval subextension has no execution implementation".into())}

    let (image, mem) = match open_program(program, o, &mut t) {
        Ok(v) => v,
        Err(()) => return platform_failed(o, &mut t, &stamp, &[]),
    };
    t.raw(&logx::program(program, &image));
    // Parameter validation runs while the platform is built, before the
    // signature model describes itself: an out-of-range value is reported and
    // the model stays armed with it, but the accumulated error fails the build
    // afterwards (`OP_FIP`). An override that matched nothing does not stop
    // the model from being configured first, so its `CF_UE` lands after the
    // signature block.
    let byte_count_low = o.byte_count.filter(|v| *v < 16);
    if let Some(v) = byte_count_low {
        t.msg('E', "OP_ULT", &format!("Parameter riscvOVPsim/cpu/sigdump/ByteCount Uns32 value {v}(0x{v:x}) is less than minimum value 16(0x10)"));
    }
    if image.xlen!=config.xlen{return Err(format!("ELF{} does not match RV{} variant",image.xlen,config.xlen))}
    let tohost = symbol(&image, "tohost");
    let entry = o.entry_address.unwrap_or_else(||if o.objects.iter().any(|(_,entry)|*entry){image.entry}else{symbol(&image, "rvtest_entry_point").unwrap_or(image.entry)});

    // The signature-dump model resolves its range while the platform is built,
    // so its `SIGNATURE_DUMP_*` block lands before the first instruction. A
    // range the model cannot arm fails the whole build (`MEM_HGM` + `OP_FIP`).
    let plan = if o.signature_dump {
        match plan_signature(&image, o, &mut t) {
            Ok(p) => p,
            Err(_) => return platform_failed(o, &mut t, &stamp, &[]),
        }
    } else {
        None
    };
    if !unknown_overrides.is_empty() {
        return platform_failed(o, &mut t, &stamp, &unknown_overrides);
    }
    if byte_count_low.is_some() {
        return platform_failed(o, &mut t, &stamp, &[]);
    }
    // exitControl's own `write_tohost` intercept announces itself while the
    // platform is built, before the first instruction runs. It is only
    // installed when the platform's semihost layer does not already own
    // `write_tohost`, i.e. when `defaultsemihost` is off.
    if o.finish_on_writetohost && !config.default_semihost {
        t.msg('I', "EXC_FW", "Intercept 'write_tohost'.");
    }

    let mut m = Machine::new(mem, entry, tohost,config);
    m.halt_pc = symbol(&image, "write_tohost");
    m.trace_stdout = o.trace;
    m.custom_control=o.custom_control;
    if o.custom_control{m.custom_exit_pc=symbol(&image,"_test_exit").map(|a|a.wrapping_add(1));if let Some(path)=&o.custom_logfile{m.logfile=Some(std::fs::File::create(path).map_err(|e|format!("cannot create customControl logfile '{path}': {e}"))?);}}
    m.finish_after = o.finish_after;
    m.finish_time = o.finish_time;
    if !o.argv.is_empty()||!o.envp.is_empty(){let mut host=semihost::Semihost::new();let top=if m.config.xlen==32{0x7fff_f000}else{0x0000_7fff_ffff_f000};let mut args=vec![program.to_owned()];args.extend(o.argv.iter().cloned());host.init_process(&mut m.x,&mut m.mem,m.config.xlen,&args,&o.envp,top)?;host.set_brk(image.segments.iter().map(|s|s.addr.saturating_add(s.memsz)).max().unwrap_or(0));m.semihost=Some(host);}
    // exitControl `constructor`: one `symbol` slot, one `address` slot and a
    // selector. Both spellings (`--exiton*` and `--finishon*`) write the same
    // slots, and giving both a symbol and an address is an error that leaves
    // the intercept disarmed.
    if o.stop_symbol.is_some() && o.stop_address.is_some() {
        t.msg('E', "EXC_NV", "Please specify one of symbol or address");
    } else if let Some(name) = &o.stop_symbol {
        match symbol(&image, name) {
            Some(a) => {
                t.msg(
                    'I',
                    "EXC_SYM",
                    &format!("Program will stop at symbol '{name}' (0x{a:x})"),
                );
                m.stop_pc = Some(a);
            }
            None => t.msg('E', "EXC_SYMNF", &format!("Cannot find symbol '{name}'")),
        }
    } else if let Some(a) = o.stop_address {
        // `vmirtGetProcessorExternalCodeDomain` only maps an address covered by
        // an executable segment of the loaded program.
        let in_code = image
            .segments
            .iter()
            .any(|s| s.flags & 1 != 0 && a >= s.addr && a < s.addr.wrapping_add(s.memsz));
        if in_code {
            t.msg('I', "EXC_ADDR", &format!("Program will stop at address 0x{a:x}"));
            m.stop_pc = Some(a);
        } else {
            t.msg(
                'E',
                "EXC_ADDRDF",
                &format!("Cannot find code domain for address 0x{a:x}"),
            );
        }
    }
    m.stop_opcode = o.finish_on_opcode;
    if o.finish_on_terminate {
        // The intercept is installed on the program's `terminate` symbol, so a
        // program without one simply never reaches it.
        m.stop_terminate = symbol(&image, "terminate");
    }
    m.ecall_reg = o.ecall_result_reg.map(|v| {
        // Only 3 (gp), 10 (a0) and 28 (t3) are selectable; a value in 3..=28
        // that is not one of them is reported and replaced by the default,
        // while a value outside that window falls back silently.
        let r = if (3..=28).contains(&v) {
            if v == 3 || v == 10 || v == 28 {
                v
            } else {
                t.msg(
                    'E',
                    "EXC_EREG",
                    &format!("Ignored Result register {v}. Use 3, 10 or 28 (default)"),
                );
                28
            }
        } else {
            28
        };
        r as usize
    });
    // `main` maps `--addressbits` to the platform mask `(1 << bits) - 1`, with
    // 0x40 meaning an all-ones mask; 0x20 is the default.
    m.addr_mask = if o.address_bits >= 64 {u64::MAX} else {(1u64 << o.address_bits)-1};
    if let Some(p) = &plan {
        m.watch_signature(p.start, p.bytes);
        m.sig_min_writes = p.min_writes;
    }
    if o.cover_requested {
        let resolve = |name: &Option<String>| -> Result<Option<u64>, String> {
            match name {
                Some(name) => Ok(Some(symbol(&image, name).or_else(|| parse_address(name)).ok_or_else(|| {
                    format!("coverage symbol or address '{name}' not found in {program}")
                })?)),
                None => Ok(None),
            }
        };
        m.cov_lo = resolve(&o.cover_start)?;
        m.cov_hi = resolve(&o.cover_finish)?;
        m.cov_on = m.cov_lo.is_none();
        let mut coverage = cov::Cov::configured(o.cover_type.as_deref().unwrap_or("basic"),o.cover_ext.as_deref(),o.cover_instructions.as_deref(),m.config.xlen)?;
        if read_coverage_inputs(o, &mut coverage, &mut t).is_err() {
            return coverage_abort(o, &mut t, &stamp);
        }
        // The model describes the instruction-coverage setup while the
        // platform is built, before the window is armed.
        t.msg(
            'I',
            "ICV_PVSN",
            &format!("parameter 'user_version' is '{}'", m.config.user_version),
        );
        t.msg('I', "ICV_ALI", "Pseudo instructions will be translated");
        if let Some(lo) = m.cov_lo {
            t.msg('I', "ICV_ST", &format!("Starting coverage at 0x{lo:x}"));
        }
        m.cov = Some(coverage);
    }
    let started = std::time::Instant::now();
    let result = m.run();
    let elapsed = started.elapsed();

    if let (Ok(path), Some(h)) = (std::env::var("RUSTISS_PCDUMP"), m.hist.as_ref()) {
        let mut body = String::new();
        for (pc, n) in h {
            let _ = writeln!(body, "{pc:08x} {n}");
        }
        let _ = std::fs::write(path, body);
    }
    if let Ok(path) = std::env::var("RUSTISS_COVDUMP") {
        if let Some(c) = &m.cov {
            let mut body = String::new();
            for (name, hits, pts) in c.rows(o.count_threshold) {
                let _ = writeln!(body, "instr {name} {hits}/{pts}");
            }
            c.dump_leaves(&mut body);
            for p in c.missed_points() {
                let _ = writeln!(body, "miss {p}");
            }
            let _ = std::fs::write(path, body);
        }
    }

    // ---- end of run ------------------------------------------------------
    // The interpreter's event stream is already ordered instruction by
    // instruction: `SFW` lines, `RISCV_IMA` warnings and raw `customControl`
    // bytes sit at the point that produced them. `ICV_FN` closed the coverage
    // window, so the document and the report are written from that offset and
    // the halt lines keep their later position.
    let mark = if m.cov_closed {
        m.cov_mark.unwrap_or(m.events.len())
    } else {
        m.events.len()
    };
    t.bytes(&m.events[..mark]);
    if m.cov_closed && o.cover_requested {
        if let Some(c) = &m.cov {
            coverage_outputs(o, c, m.cov_counted, &mut t)?;
        }
    }
    t.bytes(&m.events[mark..]);

    // `SignatureAtEnd` dumps from the `write_tohost` callback, so the
    // announcement and the words only appear for a run that reached it: an
    // exit intercept that ends the run early writes no signature at all.
    let mut sig_failed = false;
    if result.is_ok() && m.exit == Exit::Halt && o.signature_dump && o.signature_at_end {
        if plan.is_none() {
            // Without a usable range - no `SignatureFile`, or a configuration
            // failure - the model never arms its write counter, so the check
            // that runs at `write_tohost` sees no writes at all and fails.
            t.msg(
                'I',
                "SIGNATURE_DUMP_WTH",
                "Intercept 'write_tohost'. Generate Signature file",
            );
            t.msg(
                'E',
                "SIGNATURE_DUMP_SFW",
                "Failed to detect expected writes to signature region",
            );
            sig_failed = true;
        }
        if let Some(p) = &plan {
            let sig = emit_signature(p, &m.mem)?;
            t.msg(
                'I',
                "SIGNATURE_DUMP_WTH",
                "Intercept 'write_tohost'. Generate Signature file",
            );
            // The dump reaches stdout as well unless the override says
            // otherwise; the logfile always receives it.
            if o.sig_to_stdout {
                t.raw(&sig);
            }
            // The model only checks the write count when it can prove the
            // program is not a self-checking one (presence of `main`).
            sig_failed = p.min_writes > 0
                && m.sig_writes < u64::from(p.min_writes)
                && symbol(&image, "main").is_none();
            if sig_failed {
                t.msg(
                    'E',
                    "SIGNATURE_DUMP_SFW",
                    "Failed to detect expected writes to signature region",
                );
            }
            if let Some(path) = &o.sig_file {
                std::fs::write(path, &sig)
                    .map_err(|e| format!("cannot write signature file '{path}': {e}"))?;
            }
        }
    }
    // sigdump's `write_tohost` callback prints its verdict *after* the dump,
    // from the failure flag its own write counting maintains.
    if m.exit == Exit::Halt && m.ecall_reg.is_some() {
        t.raw(if sig_failed { "Test FAILED\n" } else { "Test PASSED\n" });
    }
    // A window that never reached its finish symbol still writes its document,
    // report and summary - after the signature dump, as `writeResults` does.
    if !m.cov_closed && result.is_ok() && o.cover_requested {
        if let Some(c) = &m.cov {
            coverage_outputs(o, c, m.cov_counted, &mut t)?;
        }
    }

    // Statistics. The `Info ` separator belongs to a run that ended on its own
    // `write_tohost`; an intercept that stopped the processor prints none.
    let (user, system) = logx::cpu_times();
    let final_pc = m
        .final_pc
        .unwrap_or_else(|| m.pc.wrapping_add(u64::from(m.cur_len)));
    t.raw(&logx::cpu_stats(
        variant,
        final_pc,
        m.counter,
        m.config.mips as u64,
    ));
    t.raw(&logx::time_stats(
        m.counter,
        m.config.mips as u64,
        user,
        system,
        elapsed.as_secs_f64(),
    ));
    t.raw(&logx::shutdown(&stamp));
    t.publish(o, &stamp)?;
    // The model's own error counter is what makes the process exit non-zero:
    // a signature that missed `SignatureMinWrites`, or an `ecall` the semihost
    // layer rejected.
    if sig_failed || m.exit == Exit::Syscall {
        return Err(String::new());
    }
    result
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("riscvOVPsim: error: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        // Errors that the platform already reported in the transcript carry an
        // empty message: the exit status is the only thing left to say.
        Err(e) => {
            if !e.is_empty() {
                eprintln!("riscvOVPsim: error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}