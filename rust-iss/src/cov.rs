//! RV32I instruction-coverage model: the node tree the OVP
//! `riscvInstructionCoverage` model builds, the per-execution counters, and the
//! report writer.
//!
//! Tree shape is taken from the model's own report output
//! (`riscv-test-suite/rv32i_m/I/basic.coverage.txt`) and cross-checked against
//! the counting functions of the model blob:
//!
//!   cross{rs1_rs2{c00,c01,c10,c11}}   regNegative(rs1), regNegative(rs2)
//!   cross{nord_rs1_rs2{...}}          same, branch operand slots
//!   cross{rs1_imm{...}}               regNegative(rs1), imm < 0
//!   rd{gpr{...},sign{neg,pos}}        destination register / its sign
//!   imm{sign{neg,pos}}                immediate sign
//!   offset{sign{neg,pos,zero}}        sign of (target - pc)
//!
//! Every instruction also carries a hidden `asm_count` fact (executions), which
//! the report only uses for the `Unique instructions` line.

/// ABI names in x0..x31 order.
const GPR_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// gpr leaves are stored in the alphabetical order the model creates them in.
const GPR_LEAF_ORDER: [&str; 32] = [
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "gp", "ra", "s0", "s1", "s2", "s3", "s4",
    "s5", "s6", "s7", "s8", "s9", "s10", "s11", "sp", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "tp", "zero",
];

pub fn gpr_name(i: usize) -> &'static str {
    GPR_NAMES[i & 31]
}


#[derive(Clone, Copy)]
pub enum Kid {
    /// cross/<kind>/cXY
    Cross(&'static str),
    /// rd{gpr,sign?}
    Rd(bool),
    Rs1(bool),
    Rs2(bool),
    /// imm{sign{neg,pos}}
    Imm,
    /// offset{sign{neg,pos,zero}}
    Offset,
}

const fn cross_kind() -> &'static [Kid] {
    &[Kid::Cross("rs1_rs2"), Kid::Rd(true), Kid::Rs1(true), Kid::Rs2(true)]
}

/// Per-mnemonic child list, in report order.
pub const MODEL: &[(&str, &[Kid])] = &[
    ("add", cross_kind()),
    ("addi", &[Kid::Cross("rs1_imm"), Kid::Imm, Kid::Rd(true), Kid::Rs1(true)]),
    ("and", cross_kind()),
    ("andi", &[Kid::Cross("rs1_imm"), Kid::Imm, Kid::Rd(true), Kid::Rs1(true)]),
    ("auipc", &[Kid::Rd(true)]),
    ("beq", &[Kid::Cross("nord_rs1_rs2"), Kid::Offset, Kid::Rs1(true), Kid::Rs2(true)]),
    ("bge", &[Kid::Cross("nord_rs1_rs2"), Kid::Offset, Kid::Rs1(true), Kid::Rs2(true)]),
    ("bgeu", &[Kid::Cross("nord_rs1_rs2"), Kid::Offset, Kid::Rs1(true), Kid::Rs2(true)]),
    ("blt", &[Kid::Cross("nord_rs1_rs2"), Kid::Offset, Kid::Rs1(true), Kid::Rs2(true)]),
    ("bltu", &[Kid::Cross("nord_rs1_rs2"), Kid::Offset, Kid::Rs1(true), Kid::Rs2(true)]),
    ("bne", &[Kid::Cross("nord_rs1_rs2"), Kid::Offset, Kid::Rs1(true), Kid::Rs2(true)]),
    ("fence", &[]),
    ("jal", &[Kid::Rd(false)]),
    ("jalr", &[Kid::Imm, Kid::Rd(false)]),
    ("lb", &[Kid::Imm, Kid::Rd(false)]),
    ("lbu", &[Kid::Imm, Kid::Rd(false)]),
    ("lh", &[Kid::Imm, Kid::Rd(false)]),
    ("lhu", &[Kid::Imm, Kid::Rd(false)]),
    ("lui", &[Kid::Rd(true)]),
    ("lw", &[Kid::Imm, Kid::Rd(false)]),
    ("or", cross_kind()),
    ("ori", &[Kid::Cross("rs1_imm"), Kid::Imm, Kid::Rd(true), Kid::Rs1(true)]),
    ("sb", &[Kid::Imm, Kid::Rs2(false)]),
    ("sh", &[Kid::Imm, Kid::Rs2(false)]),
    ("sll", &[Kid::Rd(true), Kid::Rs1(true), Kid::Rs2(false)]),
    ("slli", &[Kid::Rd(true), Kid::Rs1(true)]),
    ("slt", &[Kid::Cross("rs1_rs2"), Kid::Rd(false), Kid::Rs1(true), Kid::Rs2(true)]),
    ("slti", &[Kid::Cross("rs1_imm"), Kid::Imm, Kid::Rd(false), Kid::Rs1(true)]),
    ("sltiu", &[Kid::Cross("rs1_imm"), Kid::Imm, Kid::Rd(false), Kid::Rs1(true)]),
    ("sltu", &[Kid::Cross("rs1_rs2"), Kid::Rd(false), Kid::Rs1(true), Kid::Rs2(true)]),
    ("sra", &[Kid::Rd(true), Kid::Rs1(true), Kid::Rs2(false)]),
    ("srai", &[Kid::Rd(true), Kid::Rs1(true)]),
    ("srl", &[Kid::Rd(true), Kid::Rs1(true), Kid::Rs2(false)]),
    ("srli", &[Kid::Rd(true), Kid::Rs1(true)]),
    ("sub", cross_kind()),
    ("sw", &[Kid::Imm, Kid::Rs2(false)]),
    ("wfi", &[]),
    ("xor", cross_kind()),
    ("xori", &[Kid::Cross("rs1_imm"), Kid::Imm, Kid::Rd(true), Kid::Rs1(true)]),
];

pub struct Node {
    pub name: &'static str,
    pub hits: u64,
    pub kids: Vec<Node>,
    binary: Option<(u64, u64)>,
}

impl Node {
    fn leaf(name: &'static str) -> Node {
        Node {
            name,
            hits: 0,
            kids: Vec::new(),
            binary: binary_bin(name),
        }
    }

    fn branch(name: &'static str, kids: Vec<Node>) -> Node {
        Node {
            name,
            hits: 0,
            kids,
            binary: binary_bin(name),
        }
    }

    /// Total coverage points below this node; a childless instruction is
    /// itself one point (`wfi 0/1`).
    pub fn points(&self) -> u64 {
        if self.kids.is_empty() {
            1
        } else {
            self.kids.iter().map(|k| k.points()).sum()
        }
    }

    /// Coverage points hit below this node, as `reportNode` counts them: a
    /// leaf is hit once its count reaches `threshold`, so `gpr 32/32` counts
    /// distinct registers while each register leaf still reports its raw
    /// execution count.
    pub fn hit_count(&self, threshold: u32) -> u64 {
        if self.kids.is_empty() {
            u64::from(self.hits >= u64::from(threshold))
        } else {
            self.kids.iter().map(|k| k.hit_count(threshold)).sum()
        }
    }

    /// Leaves below `self` that were never seen at all, as `missedNode`
    /// (0x155970) decides it: the test is `count == 0`, not `< threshold`.
    pub fn missed_zero(&self, path: &str, out: &mut Vec<String>) {
        if self.kids.is_empty() {
            if self.hits == 0 && !path.is_empty() {
                out.push(path.to_string());
            }
            return;
        }
        for k in &self.kids {
            let p = if path.is_empty() {
                k.name.to_string()
            } else {
                format!("{path}/{}", k.name)
            };
            k.missed_zero(&p, out);
        }
    }

    fn find(&mut self, path: &[&str]) -> Option<&mut Node> {
        if path.is_empty() {
            return Some(self);
        }
        let (head, rest) = path.split_first()?;
        for k in &mut self.kids {
            if k.name == *head {
                return k.find(rest);
            }
        }
        None
    }

}

pub struct InstrCov {
    pub name: &'static str,
    pub root: Node,
    pub model: &'static [Kid],
    /// executions, the model's hidden `asm_count`
    pub asm_count: u64,
}

pub struct Cov {
    pub instrs: Vec<InstrCov>,
    visible: Vec<bool>,
    xlen: u32,
    report_order: Vec<usize>,
}

fn selected_instructions(selection: Option<&str>) -> Result<[bool; MODEL.len()], String> {
    let Some(selection) = selection else { return Ok([true; MODEL.len()]) };
    let mut visible = [false; MODEL.len()];
    for name in selection.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let Some(idx) = Cov::index_of(name) else {
            return Err(format!("coverage instruction '{name}' is not recognised"));
        };
        visible[idx] = true;
    }
    if !visible.iter().any(|v| *v) {
        return Err("--instructions requires at least one mnemonic".into());
    }
    Ok(visible)
}

fn gpr_node() -> Node {
    Node::branch("gpr", GPR_LEAF_ORDER.iter().map(|n| Node::leaf(n)).collect())
}

fn sign_node(kinds: &[&'static str]) -> Node {
    Node::branch("sign", kinds.iter().map(|k| Node::leaf(k)).collect())
}

fn build_instr(name: &'static str, kids: &[Kid]) -> Node {
    let mut children = Vec::new();
    for k in kids {
        children.push(match *k {
            Kid::Cross(kind) => {
                let bins = ["c00", "c01", "c10", "c11"];
                Node::branch(
                    "cross",
                    vec![Node::branch(
                        kind,
                        bins.iter().map(|b| Node::leaf(b)).collect(),
                    )],
                )
            }
            Kid::Rd(sign) | Kid::Rs1(sign) | Kid::Rs2(sign) => {
                let who = match k {
                    Kid::Rd(_) => "rd",
                    Kid::Rs1(_) => "rs1",
                    _ => "rs2",
                };
                let mut kids_v = vec![gpr_node()];
                if sign {
                    kids_v.push(sign_node(&["neg", "pos"]));
                }
                Node::branch(who, kids_v)
            }
            Kid::Imm => Node::branch("imm", vec![sign_node(&["neg", "pos"])]),
            Kid::Offset => Node::branch("offset", vec![sign_node(&["neg", "pos", "zero"])]),
        });
    }
    Node::branch(name, children)
}

impl Cov {

    pub fn new_filtered(selection: Option<&str>) -> Result<Cov, String> {
        let visible = selected_instructions(selection)?;
        let instrs = MODEL
            .iter()
            .enumerate()
            .map(|(idx, (name, kids))| InstrCov {
                name,
                root: if visible[idx] { build_instr(name, kids) } else { Node::branch(name, Vec::new()) },
                model: kids,
                asm_count: 0,
            })
            .collect();
        Ok(Cov { instrs, visible: visible.to_vec(), xlen: 32, report_order: (0..MODEL.len()).collect() })
    }

    fn ordered(&self) -> impl Iterator<Item = (usize, &InstrCov)> {
        self.report_order.iter().map(|&idx| (idx, &self.instrs[idx]))
    }

    fn visible(&self, idx: usize) -> bool {
        self.visible.get(idx).copied().unwrap_or(false)
    }

    pub fn index_of(mnemonic: &str) -> Option<usize> {
        MODEL.iter().position(|(n, _)| *n == mnemonic)
    }


    /// Count one retired instruction.
    ///
    /// `op.imm` is the decoded immediate (branch/jump displacement for
    /// control transfers), `op.offset` the sign-magnitude input the model
    /// derives from `target - pc`.
    pub fn record(&mut self, idx: usize, op: &Operands) {
        self.record64(idx, &Operands64 {
            rd: op.rd, rs1: op.rs1, rs2: op.rs2,
            imm: i64::from(op.imm), offset: i64::from(op.offset),
            rd_val: u64::from(op.rd_val), rs1_val: u64::from(op.rs1_val), rs2_val: u64::from(op.rs2_val),
        });
    }

    /// Instruction-level report rows: (name, points hit, points total) for
    /// every instruction, with `threshold` deciding a hit.
    pub fn rows(&self, threshold: u32) -> Vec<(&'static str, u64, u64)> {
        self.ordered()
            .filter(|(idx, _)| self.visible(*idx))
            .map(|(_, i)| {
                let (h, t) = instr_points(i, threshold);
                (i.name, h, t)
            })
            .collect()
    }

    pub fn dump_leaves(&self, out: &mut String) {
        fn walk(n: &Node, path: &str, out: &mut String) {
            let p = if path.is_empty() {
                n.name.to_string()
            } else {
                format!("{path}/{}", n.name)
            };
            if n.kids.is_empty() {
                out.push_str(&format!("{p} {}\n", n.hits));
            } else {
                for k in &n.kids {
                    walk(k, &p, out);
                }
            }
        }
        for (idx, i) in self.ordered() {
            if self.visible(idx) {
                walk(&i.root, "", out);
            }
        }
    }

    pub fn missed_points(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (idx, i) in self.ordered() {
            if !self.visible(idx) {
                continue;
            }
            if i.root.kids.is_empty() {
                if i.asm_count == 0 {
                    out.push(i.name.to_string());
                }
            } else {
                i.root.missed_zero(i.name, &mut out);
            }
        }
        out
    }

    pub fn to_yaml(&self) -> String {
        fn node(n: &Node, depth: usize, out: &mut String) {
            let ind = "  ".repeat(depth);
            if n.kids.is_empty() {
                out.push_str(&format!("{ind}{}: {}\n", n.name, n.hits));
                return;
            }
            out.push_str(&format!("{ind}{}:\n", n.name));
            for k in &n.kids {
                node(k, depth + 1, out);
            }
        }
        let mut out = String::new();
        // libyaml frames the accumulator as one document: an explicit start
        // marker here and an end marker after the last mapping.
        out.push_str("---\n");
        for (idx, i) in self.ordered() {
            if !self.visible(idx) {
                continue;
            }
            out.push_str(&format!("{}:\n", i.name));
            out.push_str(&format!("  asm_count: {}\n", i.asm_count));
            for k in &i.root.kids {
                node(k, 1, &mut out);
            }
        }
        out.push_str("...\n");
        out
    }

    pub fn merge_yaml(&mut self, doc: &crate::yaml::Val) -> Vec<String> {
        use crate::yaml::Val;
        let mut unknown = Vec::new();
        let items = match doc {
            Val::Map(items) => items,
            Val::Count(_) => {
                unknown.push("(root)".to_string());
                return unknown;
            }
        };
        for (name, sub) in items {
            let Some(idx) = self.instrs.iter().position(|i| i.name == name.as_str()) else {
                unknown.push(name.clone());
                continue;
            };
            if !self.visible(idx) {
                unknown.push(name.clone());
                continue;
            }
            let instr = &mut self.instrs[idx];
            let kids = match sub {
                Val::Map(kids) => kids,
                Val::Count(_) => {
                    unknown.push(name.clone());
                    continue;
                }
            };
            for (key, v) in kids {
                if key == "asm_count" {
                    match v.as_count() {
                        Some(n) => instr.asm_count += n,
                        None => unknown.push(format!("{name}/asm_count")),
                    }
                } else {
                    apply_yaml(&mut instr.root, name, key, v, &mut unknown);
                }
            }
        }
        unknown
    }


    pub fn points(&self, threshold: u32) -> (u64, u64) {
        self.instrs
            .iter()
            .enumerate()
            .filter(|(idx, _)| self.visible(*idx))
            .fold((0, 0), |(h, t), (_, i)| {
                let (ih, it) = instr_points(i, threshold);
                (h + ih, t + it)
            })
    }

    /// The `Info` block `reportCoverage` (0x155b10) composes with `sprintf` and
    /// prints to stdout between two rule lines. `counted` is
    /// `*(uint *)(state + 0x44)`, which only the simulation path accumulates.
    pub fn info_block(&self, ext: Option<&str>, threshold: u32, counted: u64) -> String {
        let (ihit, itotal) = self.unique_instructions();
        let (phit, ptotal) = self.points(threshold);
        format!(
            "Info TOTAL INSTRUCTION COVERAGE : {}\n\
             Info   Threshold             : {threshold}\n\
             Info   Instructions counted  : {counted}\n\
             Info   Unique instructions   : {ihit}/{itotal} : {:6.2}%\n\
             Info   Coverage points hit   : {phit}/{ptotal} : {:6.2}%\n",
            ext.unwrap_or(DEFAULT_EXT),
            pct(u64::from(ihit), u64::from(itotal)),
            pct(phit, ptotal)
        )
    }

    /// Instruction counts for the `Unique instructions` line: executed vs
    /// modelled.
    pub fn unique_instructions(&self) -> (u32, u32) {
        let hit = self
            .instrs
            .iter()
            .enumerate()
            .filter(|(idx, i)| self.visible(*idx) && i.asm_count > 0)
            .count();
        let total = self.visible.iter().filter(|visible| **visible).count();
        (hit as u32, total as u32)
    }

    /// The text report `cdReport` writes (`basic.coverage.txt`).
    ///
    /// Line shapes are the model's own format strings, recovered from
    /// `reportNode` at 0x1555b0:
    ///
    /// * node header, depth >= 1: `"%s%-15s\n"` with `4 * depth` spaces;
    /// * leaf: `"%s%-10s %3u/%u : %6.2f%%%s\n"` where the trailing `%s` is
    ///   `" ZERO"` when the count is zero;
    /// * node summary, depth >= 1: `"%s%s %u/%u : %6.2f%%\n"`;
    /// * a childless instruction is one point, counted from its hidden
    ///   `asm_count` (`cdNodeByName(node, "asm_count")`).
    pub fn write_report(
        &self,
        ext: Option<&str>,
        threshold: u32,
        show_uncovered: bool,
        counted: u64,
    ) -> String {
        let mut out = String::new();
        let (_, itotal) = self.unique_instructions();
        out.push_str("Imperas RISC-V Instruction Coverage Report\n\n");
        match ext {
            Some(e) => out.push_str(&format!("Extension : {e}, instructions: {itotal}\n")),
            None => out.push_str(&format!("Instructions: {itotal}\n")),
        }
        let (_, pts_total) = self.points(threshold);
        for (idx, i) in self.ordered() {
            if !self.visible(idx) {
                continue;
            }
            if i.root.kids.is_empty() {
                let ind = " ".repeat(4);
                let hit = u64::from(i.asm_count >= u64::from(threshold));
                out.push_str(&format!("{ind}{:<15}\n", i.name));
                out.push_str(&format!(
                    "{ind}{} {hit}/1 : {:6.2}%\n",
                    i.name,
                    pct(hit, 1)
                ));
            } else {
                emit_node(&i.root, 1, threshold, &mut out);
            }
        }
        if show_uncovered {
            let m = self.missed_points();
            out.push_str("Coverage points missed:\n");
            for p in &m {
                out.push_str(&format!("  {p}\n"));
            }
            out.push_str(&format!("Coverage points missed: {}/{pts_total}\n\n", m.len()));
        }
        out.push_str(&self.info_block(ext, threshold, counted));
        out
    }
}

/// Extension label used when `--extensions` is absent (`DAT_00191f0d`).
const DEFAULT_EXT: &str = "I";

/// `reportNode`'s accounting for one instruction, without writing text: a
/// childless instruction is a single point decided by its hidden `asm_count`
/// (its own `hits` never reach the tree), anything else sums its leaves.
fn instr_points(i: &InstrCov, threshold: u32) -> (u64, u64) {
    if i.root.kids.is_empty() {
        (u64::from(i.asm_count >= u64::from(threshold)), 1)
    } else {
        (i.root.hit_count(threshold), i.root.points())
    }
}

/// The model's percentage: `100.0f * hit / total`, `100.0` when everything is
/// hit, `0.0` when there is nothing to hit. All arithmetic is `float`, matching
/// `(float)uVar4 * 100.0 / (float)uVar1`.
fn pct(hit: u64, total: u64) -> f64 {
    if total != 0 && hit < total {
        f64::from((hit as f32) * 100.0f32 / (total as f32))
    } else if total == 0 {
        0.0
    } else {
        100.0
    }
}

fn emit_node(n: &Node, depth: usize, threshold: u32, out: &mut String) -> (u64, u64) {
    let ind = " ".repeat(depth * 4);
    if n.kids.is_empty() {
        let hits = n.hits as u32;
        let p = pct(u64::from(hits), u64::from(threshold));
        let name = n.name;
        let zero = if hits == 0 { " ZERO" } else { "" };
        out.push_str(&format!(
            "{ind}{name:<10} {hits:>3}/{threshold} : {p:6.2}%{zero}\n"
        ));
        return (u64::from(hits >= threshold), 1);
    }
    out.push_str(&format!("{ind}{:<15}\n", n.name));
    let mut hit = 0u64;
    let mut total = 0u64;
    for k in &n.kids {
        let (h, t) = emit_node(k, depth + 1, threshold, out);
        hit += h;
        total += t;
    }
    out.push_str(&format!(
        "{ind}{} {hit}/{total} : {:6.2}%\n",
        n.name,
        pct(hit, total)
    ));
    (hit, total)
}

pub struct Operands {
    pub rd: usize,
    pub rs1: usize,
    pub rs2: usize,
    pub imm: i32,
    pub offset: i32,
    pub rd_val: u32,
    pub rs1_val: u32,
    pub rs2_val: u32,
}

/// Full-width retired operands. Source values are sampled before execution;
/// the destination value is sampled after execution (x0 remains zero).
pub struct Operands64 {
    pub rd: usize,
    pub rs1: usize,
    pub rs2: usize,
    pub imm: i64,
    pub offset: i64,
    pub rd_val: u64,
    pub rs1_val: u64,
    pub rs2_val: u64,
}
/// `yamlReadItem` (0x154c90) recursion: find the child node called `key` under
/// `n` and add its count, or keep descending while the document nests. An
/// unknown key is collected for the `ICV_YNNF` message instead of being an
/// error, which is what the model does before its `ICV_YINC` note.
fn apply_yaml(
    n: &mut Node,
    path: &str,
    key: &str,
    v: &crate::yaml::Val,
    unknown: &mut Vec<String>,
) {
    let here = format!("{path}/{key}");
    let kid = match n.kids.iter_mut().find(|k| k.name == key) {
        Some(k) => k,
        None => {
            unknown.push(here);
            return;
        }
    };
    if kid.kids.is_empty() {
        match v.as_count() {
            Some(c) => kid.hits += c,
            None => unknown.push(here),
        }
        return;
    }
    match v {
        crate::yaml::Val::Map(items) => {
            for (k, sub) in items {
                apply_yaml(kid, &here, k, sub, unknown);
            }
        }
        crate::yaml::Val::Count(_) => unknown.push(here),
    }
}

/// Authored model trees, compiled from the supplied original reports.
const REPORT_MODELS: &[(u32, &str, &str, &str)] = &[
    (32, "C", "basic", include_str!("../../riscv-test-suite/rv32i_m/C/basic.coverage.txt")),
    (32, "C", "extended", include_str!("../../riscv-test-suite/rv32i_m/C/extended.coverage.txt")),
    (32, "F", "basic", include_str!("../../riscv-test-suite/rv32i_m/F/basic.coverage.txt")),
    (32, "I", "basic", include_str!("../../riscv-test-suite/rv32i_m/I/basic.coverage.txt")),
    (32, "I", "extended", include_str!("../../riscv-test-suite/rv32i_m/I/extended.coverage.txt")),
    (32, "M", "basic", include_str!("../../riscv-test-suite/rv32i_m/M/basic.coverage.txt")),
    (32, "M", "extended", include_str!("../../riscv-test-suite/rv32i_m/M/extended.coverage.txt")),
    (32, "P", "basic", include_str!("../../riscv-test-suite/rv32i_m/P/basic.coverage.txt")),
    (32, "Vb", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vb/basic.coverage.txt")),
    (32, "Vf", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vf/basic.coverage.txt")),
    (32, "Vi", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vi/basic.coverage.txt")),
    (32, "Vm", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vm/basic.coverage.txt")),
    (32, "Vp", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vp/basic.coverage.txt")),
    (32, "Vr", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vr/basic.coverage.txt")),
    (32, "Vx", "basic", include_str!("../../riscv-test-suite/rv32i_m/Vx/basic.coverage.txt")),
    (32, "Zba", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zba/basic.coverage.txt")),
    (32, "Zba", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zba/extended.coverage.txt")),
    (32, "Zbb", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zbb/basic.coverage.txt")),
    (32, "Zbb", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zbb/extended.coverage.txt")),
    (32, "Zbc", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zbc/basic.coverage.txt")),
    (32, "Zbc", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zbc/extended.coverage.txt")),
    (32, "Zbkb", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zbkb/basic.coverage.txt")),
    (32, "Zbkb", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zbkb/extended.coverage.txt")),
    (32, "Zbkc", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zbkc/basic.coverage.txt")),
    (32, "Zbkc", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zbkc/extended.coverage.txt")),
    (32, "Zbkx", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zbkx/basic.coverage.txt")),
    (32, "Zbkx", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zbkx/extended.coverage.txt")),
    (32, "Zbs", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zbs/basic.coverage.txt")),
    (32, "Zbs", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zbs/extended.coverage.txt")),
    (32, "Zicsr", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zicsr/basic.coverage.txt")),
    (32, "Zicsr", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zicsr/extended.coverage.txt")),
    (32, "Zk", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zk/basic.coverage.txt")),
    (32, "Zk", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zk/extended.coverage.txt")),
    (32, "Zkn", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zkn/basic.coverage.txt")),
    (32, "Zkn", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zkn/extended.coverage.txt")),
    (32, "Zknd", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zknd/basic.coverage.txt")),
    (32, "Zknd", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zknd/extended.coverage.txt")),
    (32, "Zkne", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zkne/basic.coverage.txt")),
    (32, "Zkne", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zkne/extended.coverage.txt")),
    (32, "Zknh", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zknh/basic.coverage.txt")),
    (32, "Zknh", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zknh/extended.coverage.txt")),
    (32, "Zks", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zks/basic.coverage.txt")),
    (32, "Zks", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zks/extended.coverage.txt")),
    (32, "Zksed", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zksed/basic.coverage.txt")),
    (32, "Zksed", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zksed/extended.coverage.txt")),
    (32, "Zksh", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zksh/basic.coverage.txt")),
    (32, "Zksh", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zksh/extended.coverage.txt")),
    (32, "Zmmul", "basic", include_str!("../../riscv-test-suite/rv32i_m/Zmmul/basic.coverage.txt")),
    (32, "Zmmul", "extended", include_str!("../../riscv-test-suite/rv32i_m/Zmmul/extended.coverage.txt")),
    (32, "privEPMP", "basic", include_str!("../../riscv-test-suite/rv32i_m/privEPMP/basic.coverage.txt")),
    (32, "privPMP", "basic", include_str!("../../riscv-test-suite/rv32i_m/privPMP/basic.coverage.txt")),
    (64, "C", "basic", include_str!("../../riscv-test-suite/rv64i_m/C/basic.coverage.txt")),
    (64, "C", "extended", include_str!("../../riscv-test-suite/rv64i_m/C/extended.coverage.txt")),
    (64, "D", "basic", include_str!("../../riscv-test-suite/rv64i_m/D/basic.coverage.txt")),
    (64, "F", "basic", include_str!("../../riscv-test-suite/rv64i_m/F/basic.coverage.txt")),
    (64, "I", "basic", include_str!("../../riscv-test-suite/rv64i_m/I/basic.coverage.txt")),
    (64, "I", "extended", include_str!("../../riscv-test-suite/rv64i_m/I/extended.coverage.txt")),
    (64, "M", "basic", include_str!("../../riscv-test-suite/rv64i_m/M/basic.coverage.txt")),
    (64, "M", "extended", include_str!("../../riscv-test-suite/rv64i_m/M/extended.coverage.txt")),
    (64, "P", "basic", include_str!("../../riscv-test-suite/rv64i_m/P/basic.coverage.txt")),
    (64, "Zba", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zba/basic.coverage.txt")),
    (64, "Zba", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zba/extended.coverage.txt")),
    (64, "Zbb", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zbb/basic.coverage.txt")),
    (64, "Zbb", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zbb/extended.coverage.txt")),
    (64, "Zbc", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zbc/basic.coverage.txt")),
    (64, "Zbc", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zbc/extended.coverage.txt")),
    (64, "Zbkb", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zbkb/basic.coverage.txt")),
    (64, "Zbkb", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zbkb/extended.coverage.txt")),
    (64, "Zbkc", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zbkc/basic.coverage.txt")),
    (64, "Zbkc", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zbkc/extended.coverage.txt")),
    (64, "Zbkx", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zbkx/basic.coverage.txt")),
    (64, "Zbkx", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zbkx/extended.coverage.txt")),
    (64, "Zbs", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zbs/basic.coverage.txt")),
    (64, "Zbs", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zbs/extended.coverage.txt")),
    (64, "Zicsr", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zicsr/basic.coverage.txt")),
    (64, "Zicsr", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zicsr/extended.coverage.txt")),
    (64, "Zk", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zk/basic.coverage.txt")),
    (64, "Zk", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zk/extended.coverage.txt")),
    (64, "Zkn", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zkn/basic.coverage.txt")),
    (64, "Zkn", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zkn/extended.coverage.txt")),
    (64, "Zknd", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zknd/basic.coverage.txt")),
    (64, "Zknd", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zknd/extended.coverage.txt")),
    (64, "Zkne", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zkne/basic.coverage.txt")),
    (64, "Zkne", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zkne/extended.coverage.txt")),
    (64, "Zknh", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zknh/basic.coverage.txt")),
    (64, "Zknh", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zknh/extended.coverage.txt")),
    (64, "Zks", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zks/basic.coverage.txt")),
    (64, "Zks", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zks/extended.coverage.txt")),
    (64, "Zksed", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zksed/basic.coverage.txt")),
    (64, "Zksed", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zksed/extended.coverage.txt")),
    (64, "Zksh", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zksh/basic.coverage.txt")),
    (64, "Zksh", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zksh/extended.coverage.txt")),
    (64, "Zmmul", "basic", include_str!("../../riscv-test-suite/rv64i_m/Zmmul/basic.coverage.txt")),
    (64, "Zmmul", "extended", include_str!("../../riscv-test-suite/rv64i_m/Zmmul/extended.coverage.txt")),
    (64, "privEPMP", "basic", include_str!("../../riscv-test-suite/rv64i_m/privEPMP/basic.coverage.txt")),
    (64, "privPMP", "basic", include_str!("../../riscv-test-suite/rv64i_m/privPMP/basic.coverage.txt")),
];

fn report_tree(report: &'static str) -> Vec<Node> {
    let mut roots: Vec<Node> = Vec::new();
    let mut path: Vec<&'static str> = Vec::new();
    for line in report.lines() {
        let depth = (line.len() - line.trim_start().len()) / 4;
        if depth == 0 { continue; }
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { continue };
        let second = words.next();
        if second.is_some() && !second.unwrap().contains('/') { continue; }
        if path.get(depth - 1).copied() == Some(name) { continue; }
        path.truncate(depth - 1);
        if depth == 1 {
            roots.push(Node::branch(name, Vec::new()));
        } else if let Some(root) = roots.last_mut() {
            if let Some(parent) = root.find(&path[1..]) {
                parent.kids.push(Node::branch(name, Vec::new()));
            }
        }
        path.push(name);
    }
    roots
}

impl Cov {
    /// Select an evidenced model. Unsupported model taxonomies fail explicitly,
    /// rather than silently turning a rich model into instruction counters.
    pub fn configured(kind: &str, extensions: Option<&str>, instructions: Option<&str>, xlen: u32) -> Result<Self, String> {
        if xlen != 32 && xlen != 64 { return Err("coverage XLEN must be 32 or 64".into()); }
        if kind != "basic" && kind != "extended" {
            return Err(format!("coverage model '{kind}' has no supplied executable counting specification (pseudo model is unavailable)"));
        }
        let mut cov = Self::new_filtered(None)?;
        cov.xlen = xlen;
        cov.visible.fill(false);
        let ext = extensions.unwrap_or("I");
        let mut selected = Vec::new();
        for item in ext.split(|c: char| c == ',' || c == '+' || c == '_' || c.is_whitespace()).filter(|s| !s.is_empty()) {
            let item = item.strip_prefix("RV").unwrap_or(item);
            if REPORT_MODELS.iter().any(|(x,e,k,_)| *x == xlen && *e == item && *k == kind) {
                selected.push(item);
            } else if item.chars().all(|c| "IEMAFDC".contains(c)) {
                for n in 0..item.len() { selected.push(&item[n..n+1]); }
            } else { return Err(format!("no {kind} coverage metadata for extension '{item}' at RV{xlen}")); }
        }
        if selected.is_empty() { return Err("coverage extensions cannot be empty".into()); }
        for extension in selected {
            let Some((_,_,_,report)) = REPORT_MODELS.iter().find(|(x,e,k,_)| *x == xlen && *e == extension && *k == kind) else {
                return Err(format!("no {kind} coverage metadata for extension '{extension}' at RV{xlen}"));
            };
            for root in report_tree(report) {
                validate_counting_tree(&root)?;
                if let Some(idx) = cov.instrs.iter().position(|i| i.name == root.name) {
                    cov.instrs[idx].root = root;
                    cov.visible[idx] = true;
                } else {
                    cov.instrs.push(InstrCov { name: root.name, root, model: &[], asm_count: 0 });
                    cov.visible.push(true);
                }
            }
        }
        if let Some(selection) = instructions {
            let mut visible = vec![false; cov.instrs.len()];
            for name in selection.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                let Some(idx) = cov.instrs.iter().position(|i| i.name == name) else { return Err(format!("coverage instruction '{name}' is not recognised")); };
                if !cov.visible[idx] { return Err(format!("coverage instruction '{name}' is outside selected extensions")); }
                visible[idx] = true;
            }
            if !visible.iter().any(|v| *v) { return Err("--instructions requires at least one mnemonic".into()); }
            cov.visible = visible;
        }
        cov.report_order = (0..cov.instrs.len()).collect();
        cov.report_order.sort_by_key(|&idx| cov.instrs[idx].name);
        Ok(cov)
    }

    pub fn record_named(&mut self, mnemonic: &str, op: &Operands64) -> bool {
        let Some(idx) = self.instrs.iter().position(|i| i.name == mnemonic) else { return false };
        self.record64(idx, op);
        true
    }

    pub fn record64(&mut self, idx: usize, op: &Operands64) {
        if !self.visible(idx) { return; }
        let instruction = &mut self.instrs[idx];
        instruction.asm_count += 1;
        count_tree(&mut instruction.root, op, self.xlen);
    }
}

fn validate_counting_tree(root: &Node) -> Result<(), String> {
    for kid in &root.kids {
        let valid = match kid.name {
            "rd" | "rs1" | "rs2" => kid.kids.iter().all(|n| matches!(n.name, "gpr" | "sign" | "value")),
            "imm" | "offset" => kid.kids.iter().all(|n| matches!(n.name, "sign" | "value")),
            "compare" => kid.kids.iter().all(|n| matches!(n.name, "rd_rs1" | "rd_rs2" | "rs1_rs2")),
            "cross" => kid.kids.iter().all(|n| matches!(n.name, "rs1_rs2" | "nord_rs1_rs2" | "rs1_imm")),
            _ => false,
        };
        if !valid { return Err(format!("coverage counting semantics unavailable for {}/{}", root.name, kid.name)); }
        for category in &kid.kids {
            if category.name == "value" && category.kids.iter().any(|bin| bin.binary.is_none()) {
                return Err(format!("unsupported nonbinary value bin in {}/{}/value", root.name, kid.name));
            }
        }
    }
    Ok(())
}

fn count_tree(root: &mut Node, op: &Operands64, xlen: u32) {
    let negative = |v: u64| v & (1u64 << (xlen - 1)) != 0;
    for kid in &mut root.kids {
        match kid.name {
            "compare" => for pair in &mut kid.kids {
                let equal = match pair.name { "rd_rs1" => op.rd == op.rs1, "rd_rs2" => op.rd == op.rs2, _ => op.rs1 == op.rs2 };
                if let Some(n) = pair.find(&[if equal { "==" } else { "!=" }]) { n.hits += 1; }
            },
            "cross" => for pair in &mut kid.kids {
                let a = negative(op.rs1_val);
                let b = if pair.name == "rs1_imm" { op.imm < 0 } else { negative(op.rs2_val) };
                let name = match (a,b) { (false,false) => "c00", (false,true) => "c01", (true,false) => "c10", (true,true) => "c11" };
                if let Some(n) = pair.find(&[name]) { n.hits += 1; }
            },
            role => {
                let (reg, value, signed) = match role {
                    "rd" => (op.rd, op.rd_val, if negative(op.rd_val) { -1 } else { 1 }),
                    "rs1" => (op.rs1, op.rs1_val, if negative(op.rs1_val) { -1 } else { 1 }),
                    "rs2" => (op.rs2, op.rs2_val, if negative(op.rs2_val) { -1 } else { 1 }),
                    "imm" => (0, op.imm as u64, op.imm.signum()),
                    _ => (0, op.offset as u64, op.offset.signum()),
                };
                for category in &mut kid.kids {
                    match category.name {
                        "gpr" => if let Some(n) = category.find(&[gpr_name(reg)]) { n.hits += 1; },
                        "sign" => {
                            let sign = if signed < 0 { "neg" } else if signed == 0 && role == "offset" { "zero" } else { "pos" };
                            if let Some(n) = category.find(&[sign]) { n.hits += 1; }
                        },
                        "value" => for bin in &mut category.kids {
                            if let Some((expected, mask)) = bin.binary {
                                if value & mask == expected { bin.hits += 1; }
                            }
                        },
                        _ => unreachable!("validated coverage taxonomy"),
                    }
                }
            }
        }
    }
}

fn binary_bin(name: &str) -> Option<(u64, u64)> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b == b'0' || b == b'1') { return None; }
    Some((u64::from_str_radix(name, 2).ok()?, u64::MAX >> (64 - name.len())))
}
