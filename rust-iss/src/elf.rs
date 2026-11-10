//! Bounds-checked ELF32/ELF64 little-endian RISC-V loader metadata.
pub struct Segment {
    pub addr: u64,
    pub vaddr: u64,
    pub memsz: u64,
    pub data: Vec<u8>,
    /// ELF PF_R=4, PF_W=2, PF_X=1.
    pub flags: u32,
}
pub struct Elf {
    pub entry: u64,
    pub xlen: u32,
    pub segments: Vec<Segment>,
    pub symbols: Vec<(String,u64)>,
}
fn bytes(b: &[u8], offset: u64, size: u64) -> Result<&[u8],String> {
    let end = offset.checked_add(size).ok_or("ELF offset overflow")?;
    let start = usize::try_from(offset).map_err(|_| "ELF offset exceeds host size")?;
    let end = usize::try_from(end).map_err(|_| "ELF extent exceeds host size")?;
    b.get(start..end).ok_or_else(|| format!("truncated ELF at offset {offset}, length {size}"))
}
fn word(b: &[u8], offset: u64, size: u64) -> Result<u64,String> {
    let mut value = 0;
    for (i,&byte) in bytes(b,offset,size)?.iter().enumerate() { value |= (byte as u64) << (i*8); }
    Ok(value)
}
fn table(b: &[u8], offset: u64, count: u64, stride: u64, minimum: u64) -> Result<(),String> {
    if count == 0 { return Ok(()); }
    if stride < minimum { return Err("ELF table entry too small".into()); }
    bytes(b,offset,count.checked_mul(stride).ok_or("ELF table size overflow")?)?;
    Ok(())
}
pub fn parse(b: &[u8]) -> Result<Elf,String> {
    if bytes(b,0,16)?[..4] != *b"\x7fELF" { return Err("not an ELF file".into()); }
    let wide = match b[4] { 1 => false, 2 => true, c => return Err(format!("unsupported ELF class {c}")) };
    if b[5] != 1 { return Err("unsupported ELF byte order (need little-endian)".into()); }
    if b[6] != 1 || word(b,20,4)? != 1 { return Err("unsupported ELF version".into()); }
    if word(b,18,2)? != 243 { return Err("ELF machine is not RISC-V".into()); }
    let header = if wide { 64 } else { 52 };
    bytes(b,0,header)?;
    let width = if wide { 8 } else { 4 };
    let entry = word(b,24,width)?;
    let phoff = word(b,if wide {32} else {28},width)?;
    let shoff = word(b,if wide {40} else {32},width)?;
    let sizes = if wide {52} else {40};
    if word(b,sizes,2)? < header { return Err("ELF header too small".into()); }
    let phstride = word(b,sizes+2,2)?;
    let mut phnum = word(b,sizes+4,2)?;
    let shstride = word(b,sizes+6,2)?;
    let mut shnum = word(b,sizes+8,2)?;
    // Extended numbering is carried by section header zero.
    if shoff != 0 && (shnum == 0 || phnum == 0xffff) {
        table(b,shoff,1,shstride,if wide {64} else {40})?;
        if shnum == 0 { shnum = word(b,shoff+if wide {32} else {20},width)?; }
        if phnum == 0xffff { phnum = word(b,shoff+if wide {44} else {28},4)?; }
    } else if phnum == 0xffff { return Err("extended program count without section table".into()); }
    table(b,phoff,phnum,phstride,if wide {56} else {32})?;
    table(b,shoff,shnum,shstride,if wide {64} else {40})?;
    let mut segments = Vec::new();
    for i in 0..phnum {
        let o = phoff+i*phstride;
        if word(b,o,4)? != 1 { continue; }
        let flags = word(b,o+if wide {4} else {24},4)? as u32;
        let offset = word(b,o+if wide {8} else {4},width)?;
        let vaddr = word(b,o+if wide {16} else {8},width)?;
        let addr = word(b,o+if wide {24} else {12},width)?;
        let filesz = word(b,o+if wide {32} else {16},width)?;
        let memsz = word(b,o+if wide {40} else {20},width)?;
        if filesz > memsz { return Err(format!("segment {i} file size exceeds memory size")); }
        if memsz != 0 {
            let last = memsz-1;
            if addr.checked_add(last).is_none() || vaddr.checked_add(last).is_none() || (!wide && (addr+last > u32::MAX as u64 || vaddr+last > u32::MAX as u64)) { return Err(format!("segment {i} address overflow")); }
        }
        let data = bytes(b,offset,filesz)?.to_vec();
        segments.push(Segment { addr,vaddr,memsz,data,flags });
    }
    let mut symbols = Vec::new();
    for i in 0..shnum {
        let o = shoff+i*shstride;
        let kind = word(b,o+4,4)?;
        if kind != 2 && kind != 11 { continue; }
        let offset = word(b,o+if wide {24} else {16},width)?;
        let size = word(b,o+if wide {32} else {20},width)?;
        let link = word(b,o+if wide {40} else {24},4)?;
        let stride = word(b,o+if wide {56} else {36},width)?;
        let minimum = if wide {24} else {16};
        if stride < minimum || size % stride != 0 { return Err("invalid ELF symbol entry size".into()); }
        bytes(b,offset,size)?;
        if link >= shnum { return Err("ELF symbol string table index out of bounds".into()); }
        let strings = shoff+link*shstride;
        if word(b,strings+4,4)? != 3 { return Err("ELF symbol link is not a string table".into()); }
        let stroff = word(b,strings+if wide {24} else {16},width)?;
        let strsize = word(b,strings+if wide {32} else {20},width)?;
        let strtab = bytes(b,stroff,strsize)?;
        for k in 0..size/stride {
            let s = offset+k*stride;
            let name = word(b,s,4)?;
            if name == 0 { continue; }
            let rest = strtab.get(usize::try_from(name).map_err(|_| "symbol name offset overflow")?..).ok_or("symbol name outside string table")?;
            let end = rest.iter().position(|&c| c == 0).ok_or("unterminated ELF symbol name")?;
            let value = word(b,s+if wide {8} else {4},width)?;
            symbols.push((String::from_utf8_lossy(&rest[..end]).into_owned(),value));
        }
    }
    Ok(Elf { entry,xlen: if wide {64} else {32},segments,symbols })
}
