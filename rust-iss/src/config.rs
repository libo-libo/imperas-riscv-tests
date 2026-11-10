//! Source-derived variant and execution configuration (riscvConfigList.c).
//! Consumers: CPU decode uses extensions/xlen and Z* flags; trap/reset uses
//! reset_address/mtvec/tvec_align; memory uses unaligned and PMP; CSR access
//! uses counter masks/undefined flags. mips and mtime_hz convert instruction
//! time to simulated time; neither is a host execution-rate throttle.

pub const VARIANTS: [&str; 40] = [
    "RV32I", "RV32IM", "RV32IMC", "RV32IMCZce", "RV32IMAC", "RV32G",
    "RV32GC", "RV32GCZfinx", "RV32GCB", "RV32GCH", "RV32GCK", "RV32GCN",
    "RV32GCP", "RV32GCV", "RV32E", "RV32EC", "RV32EM", "RV64I", "RV64IM",
    "RV64IMC", "RV64IMCZce", "RV64IMAC", "RV64G", "RV64GC", "RV64GCZfinx",
    "RV64GCB", "RV64GCH", "RV64GCK", "RV64GCN", "RV64GCP", "RV64GCV",
    "RVB32I", "RVB32E", "RVB64I", "RVI20U32", "RVI20U64", "RVA20U64",
    "RVA20S64", "RVA22U64", "RVA22S64",
];

#[derive(Clone, Debug)]
pub struct CpuConfig {
    pub variant: String,
    pub xlen: u32,
    /// Architectural extension letter bits, A=0 (including U and S).
    pub extensions: u64,
    pub user_mode: bool,
    pub supervisor_mode: bool,
    pub user_version: String,
    pub priv_version: String,
    pub zfinx: bool,
    pub zcea: bool,
    pub zceb: bool,
    pub zcee: bool,
    pub zicbom: bool,
    pub zicbop: bool,
    pub zicboz: bool,
    pub zfhmin: bool,
    pub svpbmt: bool,
    pub svinval: bool,
    pub reset_address: u64,
    pub mtvec: u64,
    /// Effective writable mask; a parameter value of zero means default mask.
    pub mtvec_mask: u64,
    pub mtvec_is_ro: bool,
    pub tvec_align: u32,
    pub unaligned: bool,
    pub unaligned_amo: bool,
    pub unaligned_v: bool,
    pub wfi_is_nop: bool,
    pub wfi_resume_not_trap: bool,
    pub mips: f64,
    pub mtime_hz: f64,
    pub pmp_registers: u32,
    /// G: minimum PMP region size is 2^(G+2) bytes.
    pub pmp_grain: u32,
    pub pmp_undefined: bool,
    pub counteren_mask: u32,
    pub scounteren_zero_mask: u32,
    pub hcounteren_zero_mask: u32,
    pub noinhibit_mask: u32,
    pub cycle_undefined: bool,
    pub mcycle_undefined: bool,
    pub time_undefined: bool,
    pub instret_undefined: bool,
    pub minstret_undefined: bool,
    pub hpmcounter_undefined: bool,
    pub mhpmcounter_undefined: bool,
    pub default_semihost: bool,
    pub simulate_exceptions: bool,
}

fn letters(value: &str) -> Result<u64, String> {
    let mut bits = 0;
    for b in value.bytes() {
        if !b.is_ascii_alphabetic() { return Err(format!("invalid extension letter in {value:?}")); }
        let b = b.to_ascii_uppercase();
        if b == b'G' { bits |= letters("IMAFD")?; }
        else { bits |= 1u64 << (b - b'A'); }
    }
    Ok(bits)
}
fn unsigned(value: &str) -> Result<u64, String> {
    let (radix, digits) = if let Some(s) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        (16, s)
    } else if let Some(s) = value.strip_prefix("0b").or_else(|| value.strip_prefix("0B")) {
        (2, s)
    } else { (10, value) };
    u64::from_str_radix(digits, radix).map_err(|_| format!("invalid unsigned integer {value:?}"))
}
fn boolean(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "t" | "1" => Ok(true), "false" | "f" | "0" => Ok(false),
        _ => Err(format!("invalid boolean {value:?}")),
    }
}
fn bounded(value: &str, max: u64) -> Result<u32, String> {
    let n = unsigned(value)?;
    if n > max { Err(format!("value {value} exceeds maximum {max}")) } else { Ok(n as u32) }
}
impl CpuConfig {
    pub fn from_variant(variant: &str) -> Result<Self, String> {
        if !VARIANTS.contains(&variant) { return Err(format!("unknown CPU variant {variant:?}")); }
        let profile = variant.starts_with("RVA") || variant.starts_with("RVI");
        let base = variant.starts_with("RVB");
        let xlen = if variant.ends_with("32") || variant.starts_with("RV32") || variant.starts_with("RVB32") { 32 } else { 64 };
        let isa = if profile {
            if variant.starts_with("RVA22") { "GCB" } else { "GC" }
        } else {
            let prefix = if base { 5 } else { 4 };
            let suffix = &variant[prefix..];
            suffix.split('Z').next().unwrap_or(suffix)
        };
        let user_mode = !base;
        let supervisor_mode = !base && (!profile || variant.contains('S'));
        let mut extensions = letters(isa)?;
        if user_mode { extensions |= 1 << 20; }
        if supervisor_mode { extensions |= 1 << 18; }
        let p22 = variant.starts_with("RVA22");
        let zce = variant.ends_with("Zce");
        Ok(Self {
            variant: variant.into(), xlen, extensions, user_mode, supervisor_mode,
            user_version: "20191213".into(),
            priv_version: if profile && !p22 { "1.11" } else { "1.12" }.into(),
            zfinx: variant.ends_with("Zfinx"), zcea: zce, zceb: zce, zcee: zce,
            zicbom: p22, zicbop: p22, zicboz: p22, zfhmin: p22,
            svpbmt: p22, svinval: p22,
            reset_address: 0, mtvec: 0, mtvec_mask: u64::MAX,
            mtvec_is_ro: false, tvec_align: 0,
            unaligned: profile, unaligned_amo: false, unaligned_v: profile,
            wfi_is_nop: false, wfi_resume_not_trap: false,
            mips: 100.0, mtime_hz: 1e6,
            pmp_registers: if base || profile { 0 } else { 16 },
            pmp_grain: 0, pmp_undefined: false,
            counteren_mask: u32::MAX, scounteren_zero_mask: 0,
            hcounteren_zero_mask: 0, noinhibit_mask: 0,
            cycle_undefined: false, mcycle_undefined: false, time_undefined: false,
            instret_undefined: false, minstret_undefined: false,
            hpmcounter_undefined: false, mhpmcounter_undefined: false,
            default_semihost: true, simulate_exceptions: true,
        })
    }
    pub fn has_extension(&self, letter: char) -> bool {
        letter.is_ascii_alphabetic() && self.extensions & (1u64 << (letter.to_ascii_uppercase() as u8 - b'A')) != 0
    }
    /// Parameters are applied atomically; unknown names are never ignored.
    pub fn apply_override(&mut self, name: &str, value: &str) -> Result<(), String> {
        match name {
            "variant" => *self = Self::from_variant(value)?,
            "user_version" => self.user_version = value.to_owned(),
            "defaultsemihost" => self.default_semihost = boolean(value)?,
            "simulateexceptions" => self.simulate_exceptions = boolean(value)?,
            "reset_address" => self.reset_address = unsigned(value)?,
            "mtvec" => self.mtvec = unsigned(value)?,
            "mtvec_mask" => { let n = unsigned(value)?; self.mtvec_mask = if n == 0 { u64::MAX } else { n }; }
            "mtvec_is_ro" => self.mtvec_is_ro = boolean(value)?,
            "tvec_align" => self.tvec_align = bounded(value, 65536)?,
            "unaligned" => self.unaligned = boolean(value)?,
            "Zam" => self.unaligned_amo = boolean(value)?,
            "unalignedV" => self.unaligned_v = boolean(value)?,
            "wfi_is_nop" => self.wfi_is_nop = boolean(value)?,
            "wfi_resume_not_trap" => self.wfi_resume_not_trap = boolean(value)?,
            "mips" | "mtime_Hz" => {
                let n: f64 = value.parse().map_err(|_| format!("invalid frequency {value:?}"))?;
                if !n.is_finite() || n <= 0.0 { return Err(format!("{name} must be finite and positive")); }
                if name == "mips" { self.mips = n; } else { self.mtime_hz = n; }
            }
            "PMP_registers" => self.pmp_registers = bounded(value, if self.priv_version == "1.10" || self.priv_version == "1.11" { 16 } else { 64 })?,
            "PMP_grain" => self.pmp_grain = bounded(value, 29)?,
            "PMP_undefined" => self.pmp_undefined = boolean(value)?,
            "counteren_mask" => self.counteren_mask = bounded(value, u32::MAX as u64)?,
            "scounteren_zero_mask" => self.scounteren_zero_mask = bounded(value, u32::MAX as u64)?,
            "hcounteren_zero_mask" => self.hcounteren_zero_mask = bounded(value, u32::MAX as u64)?,
            "noinhibit_mask" => self.noinhibit_mask = bounded(value, u32::MAX as u64)?,
            "cycle_undefined" => self.cycle_undefined = boolean(value)?,
            "mcycle_undefined" => self.mcycle_undefined = boolean(value)?,
            "time_undefined" => self.time_undefined = boolean(value)?,
            "instret_undefined" => self.instret_undefined = boolean(value)?,
            "minstret_undefined" => self.minstret_undefined = boolean(value)?,
            "hpmcounter_undefined" => self.hpmcounter_undefined = boolean(value)?,
            "mhpmcounter_undefined" => self.mhpmcounter_undefined = boolean(value)?,
            "misa_MXL" => self.xlen = bounded(value, 2).and_then(|n| if n == 0 { Err("misa_MXL must be 1 or 2".into()) } else { Ok(n * 32) })?,
            "misa_Extensions" | "add_Extensions" | "sub_Extensions" => {
                let bits = if name == "misa_Extensions" { bounded(value, (1 << 26) - 1)? as u64 } else { letters(value)? };
                self.extensions = match name { "add_Extensions" => self.extensions | bits, "sub_Extensions" => self.extensions & !bits, _ => bits };
                self.user_mode = self.has_extension('U');
                self.supervisor_mode = self.has_extension('S');
            }
            "priv_version" => {
                let v = match value { "1.10" | "20171117" => "1.10", "1.11" | "20190608" => "1.11", "1.12" | "20211203" => "1.12", _ => return Err(format!("unsupported priv_version {value:?}")) };
                if v != "1.12" && self.pmp_registers > 16 { return Err("priv_version before 1.12 permits at most 16 PMP entries".into()); }
                self.priv_version = v.into();
            }
            _ => return Err(format!("unsupported CPU override {name:?}")),
        }
        Ok(())
    }
}
