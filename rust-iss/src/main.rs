//! Sparse-memory RV32/RV64 integer interpreter and riscvOVPsim-compatible driver.
//! Integer I/E/M/A/C execution and machine/supervisor/user privileged state are
//! implemented in `cpu`; unsupported ISA extensions fail before execution.

mod cov;
mod elf;
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
            finish_on_opcode: None,
            // Unset means the model does not read a result register at all, so
            // it prints no verdict; 3/10/28 select gp/a0/t3.
            ecall_result_reg: None,
            address_bits: 32,
            show_variants: false,
            version: false,
            finish_after: None,
            cover_instructions: None,
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
            // The exitControl model always finishes on the `write_tohost`
            // intercept; this option only sets a flag the model already has,
            // so it changes nothing observable (the log's `exit` line reports
            // the halt either way).
            "--finishonwritetohost" => {}
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
            "--usehwregnames" | "--trace" => {}
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
    println!("  --finishonwritetohost       accepted; write_tohost already ends every run");
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
    println!("  --usehwregnames, --trace    accepted, no effect");
    println!();
    println!("Overrides, riscvOVPsim/cpu/<path>=<value>");
    println!("  sigdump/SignatureFile, SignatureGranularity, SignatureDumpToStdout,");
    println!("          SignatureAtEnd, SignatureMinWrites, ResultReg, StartSymbol,");
    println!("          EndSymbol, StartAddress, EndAddress, BytesCount");
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
        "sigdump/bytescount" | "sigdump/bytecount" => {
            o.byte_count = Some(parse_address(value).ok_or_else(|| format!("BytesCount '{value}'"))?)
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


/// The platform's `vmiMessage(severity, code, fmt, ...)` prints
/// `<Severity> (<code>) <text>`, the shape of every transcript line in
/// `riscv-ovpsim/README.md` (`Info (OR_OF) Target 'riscvOVPsim/cpu' has object
/// file read from ...`) and of the original's own startup banner
/// (`Fatal (PER_TMO) Product riscvOVPsim version ...`).
fn vmi_message(sev: char, code: &str, text: &str) {
    let name = match sev {
        'I' => "Info",
        'W' => "Warning",
        'E' => "Error",
        'F' => "Fatal",
        _ => "Unknown severity",
    };
    println!("{name} ({code}) {text}");
}


// ---------------------------------------------------------------------------
// Program loading
// ---------------------------------------------------------------------------

fn load_program(path: &str, o: &Opts) -> Result<(elf::Elf, Memory), String> {
    let mut mem = Memory::new(o.address_bits);
    for region in &o.memories { mem.configure(region)?; }
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let mut image = elf::parse(&bytes)?;
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
/// model computes them in its `constructor` (evidence
/// `ev_18bb3b1c0403e75a7752d9fe5e0d51c0d58a492e6f5621a86aae497c6e1747b2`):
///
/// * nothing at all is generated unless `SignatureFile` names a file -- the
///   model's dump routine is entirely inside `if (state->file)`, so a missing
///   `SignatureFile` also suppresses the `SignatureDumpToStdout` copy;
/// * `StartAddress` wins over `StartSymbol`; the symbol defaults to
///   `begin_signature` and a miss disables the dump;
/// * `BytesCount` wins over the symbol/address difference;
/// * the size is snapped to granularity blocks with the model's literal
///   arithmetic `((n + 1) - g) & ~g`, applied only when `n % g != 0`;
/// * granularity must be 4 or 16, otherwise it falls back to 16.
struct SigPlan {
    start: u64,
    bytes: u64,
    gran: u32,
    min_writes: u32,
}

fn plan_signature(image: &elf::Elf, o: &Opts, warn: &mut Vec<String>) -> Option<SigPlan> {
    if o.sig_file.is_none() {
        return None;
    }
    let start = match o.start_address {
        Some(a) => a,
        None => {
            let name = o.start_symbol.as_deref().unwrap_or("begin_signature");
            match symbol(image, name) {
                Some(v) => v,
                None => {
                    warn.push(format!(
                        " Start symbol '{name}' not found, change symbol name or specify StartAddress"
                    ));
                    return None;
                }
            }
        }
    };
    let mut size = match o.byte_count {
        Some(n) => n,
        None => {
            let end = match o.end_address {
                Some(a) => a,
                None => {
                    let name = o.end_symbol.as_deref().unwrap_or("end_signature");
                    match symbol(image, name) {
                        Some(v) => v,
                        None => {
                            warn.push(format!(
                                " End symbol '{name}' not found, change symbol name or specify EndAddress or BytesCount"
                            ));
                            return None;
                        }
                    }
                }
            };
            let fwd = end.wrapping_sub(start);
            let bwd = start.wrapping_sub(end);
            fwd.min(bwd)
        }
    };
    let mut gran = o.sig_granularity;
    if gran != 4 && gran != 16 {
        warn.push(format!(
            "Signature File Granularity {gran} not valid. May be 4 or 16 byte blocks. Setting to default 16 bytes"
        ));
        gran = 16;
    }
    if size % u64::from(gran) != 0 {
        let snapped = size.wrapping_add(1).wrapping_sub(u64::from(gran)) & !u64::from(gran);
        warn.push(format!(
            "Signature size {size} is not a multiple of the granularity {gran}, using {snapped} bytes"
        ));
        size = snapped;
    }
    if size == 0 {
        warn.push(" Size is zero".to_string());
        return None;
    }
    Some(SigPlan {
        start,
        bytes: size,
        gran,
        min_writes: o.sig_min_writes,
    })
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
fn coverage_outputs(o: &Opts, cov: &cov::Cov, counted: u64, log: &mut String) -> Result<(), String> {
    let ext = o.cover_ext.as_deref();
    if let Some(path) = &o.cover_file {
        let _ = writeln!(log, "Writing coverage file {path}");
        std::fs::write(path, cov.to_yaml())
            .map_err(|e| format!("Failed to write YAML file '{path}': {e}"))?;
        let _ = writeln!(log, "Instruction Coverage finished");
    }
    if let Some(path) = &o.cover_report {
        let _ = writeln!(log, "Writing coverage report {path}");
        let body = cov.write_report(ext, o.count_threshold, o.show_uncovered, counted);
        std::fs::write(path, body).map_err(|e| format!("Failed to write report file {path}: {e}"))?;
    }
    print!(
        "Info ---------------------------------------------------\n{}{}",
        cov.info_block(ext, o.count_threshold, counted),
        "Info ---------------------------------------------------\n"
    );
    Ok(())
}

/// One `yamlReadFile` (0x155000) input: read the document, fold it into `cov`
/// and report the keys the model's tree does not know (`ICV_YNNF`).
fn read_coverage_file(
    path: &str,
    cov: &mut cov::Cov,
    log: &mut String,
    errors: &mut u32,
) -> Result<(), String> {
    let _ = writeln!(log, "Reading file {path}");
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(log, "Failed to open file {path}: {e}");
            return Ok(());
        }
    };
    match yaml::parse(&text) {
        Ok(doc) => {
            for key in cov.merge_yaml(&doc) {
                let _ = writeln!(log, "YAML content '{path}/{key}' not recognised.");
            }
        }
        Err(e) => {
            let _ = writeln!(log, "YAML content '{path}' not recognised: {e}");
            let _ = writeln!(
                log,
                "Either the cover specification is incorrect, the wrong model has been \
                 selected or the version of the saved coverage data file does not match \
                 the software"
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
    log: &mut String,
    errors: &mut u32,
) -> Result<(), String> {
    let entries = std::fs::read_dir(path).map_err(|e| format!("Failed to open directory {path}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory {path}: {e}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let child = format!("{path}/{name}");
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_file || name.len() < 6 || !child[child.len() - 5..].eq_ignore_ascii_case(".yaml") {
            continue;
        }
        read_coverage_file(&child, cov, log, errors)?;
    }
    Ok(())
}

fn read_coverage_inputs(o: &Opts, cov: &mut cov::Cov, log: &mut String) -> Result<(), String> {
    let mut errors = 0;
    if let Some(inputs) = &o.cover_inputs {
        for path in inputs.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match std::fs::metadata(path) {
                Ok(md) if md.is_file() => read_coverage_file(path, cov, log, &mut errors)?,
                Ok(md) if md.is_dir() => read_coverage_dir(path, cov, log, &mut errors)?,
                _ => { let _ = writeln!(log, "{path} is not a file or a directory"); }
            }
        }
    }
    if errors != 0 {
        return Err(format!("Detected {errors} errors so cannot continue"));
    }
    Ok(())
}

/// `--nosimulation`: merge the `--inputfiles` coverage documents into one tree
/// and write the `--outputfile` document plus the `--reportfile` text, exactly
/// as `writeResults` (0x159e80) does when no instruction was simulated.
fn report_coverage(o: &Opts) -> Result<(), String> {
    let xlen=config::CpuConfig::from_variant(o.variant.as_deref().unwrap_or("RV32I"))?.xlen;
    let mut cov = cov::Cov::configured(o.cover_type.as_deref().unwrap_or("basic"),o.cover_ext.as_deref(),o.cover_instructions.as_deref(),xlen)?;
    let mut log = String::new();
    let _ = writeln!(
        log,
        "riscvOVPsim (Rust ISS {}): coverage merge",
        env!("CARGO_PKG_VERSION")
    );
    read_coverage_inputs(o, &mut cov, &mut log)?;
    let outcome = coverage_outputs(o, &cov, 0, &mut log);
    let _ = writeln!(log, "instructions      : 0 (merged from {})", o.cover_inputs.as_deref().unwrap_or("-"));
    if let Some(path) = &o.logfile {
        std::fs::write(path, &log).map_err(|e| format!("cannot write logfile '{path}': {e}"))?;
    }
    outcome
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
    if o.nosimulation {
        return report_coverage(o);
    }
    let program = o.program.as_deref().or_else(||o.objects.first().map(|p|p.0.as_str())).ok_or("no --program or --objfile given")?;
    let variant = o.variant.as_deref().unwrap_or("RV32I");
    let mut config = config::CpuConfig::from_variant(variant)?;
    for spec in &o.ignored_overrides {let (path,value)=spec.split_once('=').ok_or("invalid CPU override")?;let name=path.strip_prefix("riscvOVPsim/cpu/").or_else(||path.strip_prefix("riscvOVPsim/")).unwrap_or(path);config.apply_override(name,value)?;}
    let unsupported=config.extensions & ![b'I',b'E',b'M',b'A',b'C',b'S',b'U'].iter().fold(0u64,|v,c|v|(1u64<<(*c-b'A')));
    if unsupported!=0||config.zfinx{return Err(format!("variant {variant} requests extensions without execution support (ISA mask 0x{unsupported:x}, Zfinx={}); supported execution is RV32/RV64 I/E/M/A/C/S/U",config.zfinx))}
    if config.zcea||config.zceb||config.zcee||config.zicbom||config.zicboz||config.zicbop||config.zfhmin||config.svpbmt||config.svinval{return Err("requested Zce/cache-block/half-float/Svpbmt/Svinval subextension has no execution implementation".into())}
    let (image, mem) = load_program(program,o)?;
    if image.xlen!=config.xlen{return Err(format!("ELF{} does not match RV{} variant",image.xlen,config.xlen))}
    let tohost = symbol(&image, "tohost");
    let entry = o.entry_address.unwrap_or_else(||if o.objects.iter().any(|(_,entry)|*entry){image.entry}else{symbol(&image, "rvtest_entry_point").unwrap_or(image.entry)});

    let mut warnings = Vec::new();
    let plan = if o.signature_dump {
        plan_signature(&image, o, &mut warnings)
    } else {
        None
    };

    let mut m = Machine::new(mem, entry, tohost,config);
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
        vmi_message('E', "EXC_NV", "Please specify one of symbol or address");
    } else if let Some(name) = &o.stop_symbol {
        match symbol(&image, name) {
            Some(a) => {
                vmi_message(
                    'I',
                    "EXC_SYM",
                    &format!("Program will stop at symbol '{name}' (0x{a:x})"),
                );
                m.stop_pc = Some(a);
            }
            None => vmi_message('E', "EXC_SYMNF", &format!("Cannot find symbol '{name}'")),
        }
    } else if let Some(a) = o.stop_address {
        // `vmirtGetProcessorExternalCodeDomain` only maps an address covered by
        // an executable segment of the loaded program.
        let in_code = image
            .segments
            .iter()
            .any(|s| s.flags & 1 != 0 && a >= s.addr && a < s.addr.wrapping_add(s.memsz));
        if in_code {
            vmi_message('I', "EXC_ADDR", &format!("Program will stop at address 0x{a:x}"));
            m.stop_pc = Some(a);
        } else {
            vmi_message(
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
                vmi_message(
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
        let mut input_log = String::new();
        read_coverage_inputs(o, &mut coverage, &mut input_log)?;
        warnings.extend(input_log.lines().map(str::to_owned));
        m.cov = Some(coverage);
    }
    let started = std::time::Instant::now();
    let result = m.run();
    let elapsed = started.elapsed();

    // exitControl's `write_tohost` callback announces itself, but only when the
    // model has a reason to be installed at all: a plain run ends on `tohost`
    // because the CPU model does, and its transcripts carry no `Intercept`
    // line (see every example in `riscv-ovpsim/README.md`).
    let control = o.stop_symbol.is_some()
        || o.stop_address.is_some()
        || o.finish_on_terminate
        || o.finish_on_opcode.is_some()
        || o.ecall_result_reg.is_some();
    if control && m.exit == Exit::Halt {
        vmi_message('I', "EXC_FW", "Intercept 'write_tohost'.");
    }

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

    let mut log = String::new();
    let _ = writeln!(
        log,
        "riscvOVPsim (Rust ISS {}): simulation",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(log, "variant           : {variant}");
    let _ = writeln!(log, "program           : {program}");
    let _ = writeln!(log, "entry             : 0x{:08x}", entry);
    if let Some(t) = tohost {
        let _ = writeln!(log, "tohost            : 0x{t:08x}");
    }
    if o.cover_requested {
        let _ = writeln!(
            log,
            "coverage          : --cover {} --outputfile {} --reportfile {}",
            o.cover_type.as_deref().unwrap_or("?"),
            o.cover_file.as_deref().unwrap_or("-"),
            o.cover_report.as_deref().unwrap_or("-")
        );
    }
    for spec in &o.ignored_overrides {let _=writeln!(log,"CPU override      : {spec}");}
    for w in &warnings {
        let _ = writeln!(log, "signdump warning  :{w}");
    }
    match &result {
        Ok(()) => {
            let how = match m.exit {
                Exit::Halt => "halt (write to tohost)".to_string(),
                Exit::Stop(reason) => format!("stop ({reason})"),
                Exit::Terminate => "stop (terminate symbol)".to_string(),
                Exit::Ecall => "stop (ecall result register)".to_string(),
                Exit::Running => "halt".to_string(),
            };
            let _ = writeln!(log, "exit              : {how}");
        }
        Err(e) => {
            let _ = writeln!(log, "exit              : ERROR: {e}");
        }
    }
    let _ = writeln!(log, "instructions      : {}", m.instret);
    let _ = writeln!(log, "wall time         : {:.3}s", elapsed.as_secs_f64());

    // The signature is generated when the simulation ends, as SignatureAtEnd
    // documents ("at the end of simulation ... on detection of call to
    // write_tohost()").
    let mut sig_failed = false;
    // `SignatureAtEnd` dumps from the `write_tohost` callback, so a run that an
    // exit intercept ended early writes no signature at all.
    if result.is_ok() && m.exit == Exit::Halt && o.signature_at_end {
        if let Some(p) = &plan {
            let sig = emit_signature(p, &m.mem)?;
            // The model only checks the write count when it can prove the
            // program is not a self-checking one (presence of `main`).
            sig_failed = p.min_writes > 0
                && m.sig_writes < u64::from(p.min_writes)
                && symbol(&image, "main").is_none();
            if sig_failed {
                warnings.push(format!(
                    "Signature Write flag not set, saw {} writes, expected at least {}",
                    m.sig_writes, p.min_writes
                ));
            }
            if let Some(path) = &o.sig_file {
                std::fs::write(path, &sig)
                    .map_err(|e| format!("cannot write signature file '{path}': {e}"))?;
                let _ = writeln!(log, "signature file    : {path} ({} bytes)", sig.len());
                if o.sig_to_stdout {
                    print!("{sig}");
                }
            }
        }
    }
    // sigdump's `write_tohost` callback prints its verdict *after* the dump,
    // from the failure flag its own write counting maintains.
    if m.exit == Exit::Halt && m.ecall_reg.is_some() {
        println!(
            "{}",
            if sig_failed {
                "Test FAILED"
            } else {
                "Test PASSED"
            }
        );
    }

    if !warnings.is_empty() {
        for w in &warnings {
            let _ = writeln!(log, "warning           :{w}");
        }
    }
    // `writeResults` (0x159e80) only publishes once the run has completed, and
    // `Instructions counted` is what the counters saw inside the window.
    let coverage = if result.is_ok() && o.cover_requested {
        match &m.cov {
            Some(c) => Some(coverage_outputs(o, c, m.cov_counted, &mut log)),
            None => None,
        }
    } else {
        None
    };
    if let Some(path) = &o.logfile {
        std::fs::write(path, &log).map_err(|e| format!("cannot write logfile '{path}': {e}"))?;
    }
    if let Some(outcome) = coverage {
        outcome?;
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
        Err(e) => {
            eprintln!("riscvOVPsim: error: {e}");
            ExitCode::FAILURE
        }
    }
}