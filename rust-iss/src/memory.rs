//! Sparse, little-endian physical memory. Region bounds are inclusive.
use std::collections::BTreeMap;

const PAGE: usize = 4096;
struct Region { low: u64, high: u64, permissions: u8 }
pub struct Memory {
    pages: BTreeMap<u64, Box<[u8; PAGE]>>,
    regions: Vec<Region>,
    mask: u64,
}
impl Memory {
    pub fn new(bits: u32) -> Self {
        let mask = if bits >= 64 { u64::MAX } else if bits == 0 { 0 } else { (1u64 << bits) - 1 };
        Self { pages: BTreeMap::new(), regions: Vec::new(), mask }
    }
    pub fn configure(&mut self, specification: &str) -> Result<(), String> {
        fn number(s: &str) -> Result<u64, String> {
            let s = s.trim();
            let (digits, radix) = if let Some(v) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) { (v,16) } else if let Some(v) = s.strip_prefix("0b") { (v,2) } else { (s,10) };
            u64::from_str_radix(digits, radix).map_err(|_| format!("invalid memory address {s}"))
        }
        let fields: Vec<&str> = specification.split(':').collect();
        let start = if fields.first().is_some_and(|s| number(s).is_ok()) { 0 } else { 1 };
        if fields.len() < start + 2 || fields.len() > start + 3 || (start == 1 && fields[0].is_empty()) {
            return Err(format!("invalid memory region {specification}: expected [name:]low:high[:permissions]"));
        }
        let low = number(fields[start])?;
        let high = number(fields[start+1])?;
        if low > high || high > self.mask { return Err("memory region outside address space".into()); }
        let mut permissions = 7;
        if let Some(text) = fields.get(start+2) {
            permissions = 0;
            for c in text.chars() {
                permissions |= match c { 'r'|'R' => 4, 'w'|'W' => 2, 'x'|'X' => 1, '-' => 0, _ => return Err(format!("invalid memory permission {c}")) };
            }
        }
        if self.regions.iter().any(|r| low <= r.high && high >= r.low) { return Err("overlapping memory regions".into()); }
        self.regions.push(Region { low, high, permissions });
        self.regions.sort_unstable_by_key(|r| r.low);
        Ok(())
    }
    fn range(&self, addr: u64, len: u64) -> Option<(u64,u64)> {
        let low = addr & self.mask;
        let high = low.checked_add(len.checked_sub(1)?)?;
        (high <= self.mask).then_some((low,high))
    }
    pub fn allowed(&self, addr: u64, len: u64, access: u8) -> bool {
        if access & !7 != 0 { return false; }
        if len == 0 { return true; }
        let Some((mut low, high)) = self.range(addr,len) else { return false; };
        if self.regions.is_empty() { return true; }
        for r in &self.regions {
            if r.high < low { continue; }
            if r.low > low || r.permissions & access != access { return false; }
            if r.high >= high { return true; }
            low = r.high + 1;
        }
        false
    }
    fn get(&self, addr: u64) -> u8 {
        self.pages.get(&(addr >> 12)).map_or(0, |p| p[(addr & 4095) as usize])
    }
    fn put(&mut self, addr: u64, value: u8) {
        self.pages.entry(addr >> 12).or_insert_with(|| Box::new([0; PAGE]))[(addr & 4095) as usize] = value;
    }
    fn read_access(&self, addr: u64, n: u32, access: u8) -> Option<u64> {
        if n == 0 || n > 8 || !self.allowed(addr,n as u64,access) { return None; }
        let addr = addr & self.mask;
        let mut value = 0;
        for i in 0..n { value |= (self.get(addr+i as u64) as u64) << (i*8); }
        Some(value)
    }
    pub fn read(&self, addr: u64, n: u32) -> Option<u64> { self.read_access(addr,n,4) }
    pub fn fetch(&self, addr: u64, n: u32) -> Option<u64> { self.read_access(addr,n,1) }
    pub fn write(&mut self, addr: u64, n: u32, value: u64) -> bool {
        if n == 0 || n > 8 || !self.allowed(addr,n as u64,2) { return false; }
        let addr = addr & self.mask;
        for i in 0..n { self.put(addr+i as u64,(value >> (i*8)) as u8); }
        true
    }
    /// Loader writes bypass region permissions, but never wrap the address space.
    pub fn load(&mut self, addr: u64, data: &[u8]) -> Result<(), String> {
        if data.is_empty() { return Ok(()); }
        let (addr,_) = self.range(addr,data.len() as u64).ok_or("load address overflow")?;
        let mut offset = 0;
        while offset < data.len() {
            let current = addr + offset as u64;
            let within = (current & 4095) as usize;
            let count = (PAGE-within).min(data.len()-offset);
            let page = self.pages.entry(current >> 12).or_insert_with(|| Box::new([0; PAGE]));
            page[within..within+count].copy_from_slice(&data[offset..offset+count]);
            offset += count;
        }
        Ok(())
    }
    /// Only allocated pages need clearing: absent pages already read as zero.
    pub fn zero(&mut self, addr: u64, len: u64) -> Result<(), String> {
        if len == 0 { return Ok(()); }
        let (low,high) = self.range(addr,len).ok_or("zero address overflow")?;
        for (&index,page) in self.pages.range_mut((low >> 12)..=(high >> 12)) {
            let start = if index == low >> 12 { (low & 4095) as usize } else { 0 };
            let end = if index == high >> 12 { (high & 4095) as usize+1 } else { PAGE };
            page[start..end].fill(0);
        }
        Ok(())
    }
}
