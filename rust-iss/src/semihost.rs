//! Proxy-kernel syscall ABI. Host descriptors are never exposed to the guest.
use crate::memory::Memory;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, Metadata};
use std::io::{Read, Write, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const EFAULT:i32=14;
fn errno(e:std::io::Error)->i32 { e.raw_os_error().unwrap_or(5) }
fn mask(x:u64,bits:u32)->u64 { if bits==32 {x as u32 as u64} else {x} }
fn signed(x:u64,bits:u32)->i64 {if bits==32 {x as u32 as i32 as i64} else {x as i64}}
fn bytes(mem:&Memory,p:u64,n:u64)->Result<Vec<u8>,i32> {
    if !mem.allowed(p,n,4) {return Err(EFAULT)}
    let size=usize::try_from(n).map_err(|_|22)?;
    let mut out=Vec::new(); out.try_reserve_exact(size).map_err(|_|12)?;
    for i in 0..n {out.push(mem.read(p+i,1).ok_or(EFAULT)? as u8)} Ok(out)
}
fn put(mem:&mut Memory,p:u64,data:&[u8])->Result<(),i32> {
    if !mem.allowed(p,data.len() as u64,2) {return Err(EFAULT)}
    for (i,b) in data.iter().enumerate() {if !mem.write(p+i as u64,1,*b as u64) {return Err(EFAULT)}} Ok(())
}
fn string(mem:&Memory,p:u64)->Result<Vec<u8>,i32> {
    let mut v=Vec::new();
    for i in 0..4096u64 {let a=p.checked_add(i).ok_or(EFAULT)?;let c=mem.read(a,1).ok_or(EFAULT)? as u8;if c==0{return Ok(v)}v.push(c)}Err(36)
}
fn path(mem:&Memory,p:u64)->Result<PathBuf,i32> {
    use std::os::unix::ffi::OsStringExt;
    Ok(std::ffi::OsString::from_vec(string(mem,p)?).into())
}

pub struct Semihost {fds:BTreeMap<i32,File>, closed:[bool;3], heap_base:u64, heap_end:u64, args:Vec<String>}
impl Default for Semihost {fn default()->Self {Self::new()}}
impl Semihost {
    pub fn new()->Self {Self{fds:BTreeMap::new(),closed:[false;3],heap_base:0,heap_end:0,args:Vec::new()}}
    pub fn set_brk(&mut self,base:u64) {self.heap_base=base;self.heap_end=base;}
    fn valid(&self,fd:i32)->bool {self.fds.contains_key(&fd)||(fd>=0&&fd<3&&!self.closed[fd as usize])}
    fn resolve(&self,dir:i32,p:PathBuf)->Result<PathBuf,i32> {
        if p.is_absolute()||dir == -100 {return Ok(p)}
        if !self.valid(dir){return Err(9)}
        use std::os::unix::io::AsRawFd;
        let host=if let Some(f)=self.fds.get(&dir){f.as_raw_fd()}else{dir};
        let base=std::fs::read_link(format!("/proc/self/fd/{host}")).map_err(errno)?;
        if !base.is_dir(){return Err(20)} Ok(base.join(p))
    }
    fn open(&mut self,p:PathBuf,flags:u64,mode:u64)->Result<u64,i32> {
        // Linux asm-generic/RISC-V open flags; unsupported semantic flags fail.
        let known=3|0x40|0x80|0x100|0x200|0x400|0x800|0x1000|0x2000|0x4000|0x8000|0x10000|0x20000|0x40000|0x80000|0x100000;
        if flags & !known !=0 || flags&3==3 {return Err(22)}
        let mut o=OpenOptions::new();o.read(flags&3!=1).write(flags&3!=0).create(flags&0x40!=0).create_new(flags&0xc0==0xc0).truncate(flags&0x200!=0).append(flags&0x400!=0).mode(mode as u32);
        // Access/create flags are supplied by OpenOptions; remaining Linux flags
        // have identical numeric values on the supported Linux host.
        o.custom_flags((flags & !(3|0x40|0x80|0x200|0x400)) as i32);
        let file=o.open(p).map_err(errno)?;
        let fd=(0..i32::MAX).find(|n|!self.valid(*n)).ok_or(24)?;
        self.fds.insert(fd,file);Ok(fd as u64)
    }
    fn metadata(&self,fd:i32)->Result<Metadata,i32> {
        if let Some(f)=self.fds.get(&fd){return f.metadata().map_err(errno)}
        if !self.valid(fd){return Err(9)}
        std::fs::metadata(format!("/proc/self/fd/{fd}")).map_err(errno)
    }
    fn stat(mem:&mut Memory,p:u64,m:Metadata)->Result<u64,i32> {
        // pk's fixed-width frontend stat (not the host libc struct stat).
        let mut b=[0u8;128];
        for (off,v) in [(0,m.dev()),(8,m.ino()),(32,m.rdev()),(48,m.size()),(64,m.blocks()),(72,m.atime() as u64),(80,m.atime_nsec() as u64),(88,m.mtime() as u64),(96,m.mtime_nsec() as u64),(104,m.ctime() as u64),(112,m.ctime_nsec() as u64)] {b[off..off+8].copy_from_slice(&v.to_le_bytes())}
        for (off,v) in [(16,m.mode()),(20,m.nlink() as u32),(24,m.uid()),(28,m.gid()),(56,m.blksize() as u32)] {b[off..off+4].copy_from_slice(&v.to_le_bytes())}
        put(mem,p,&b)?;Ok(0)
    }
    pub fn handle(&mut self,regs:&mut [u64;32],mem:&mut Memory,xlen:u32)->Result<Option<i32>,String> {
        if xlen!=32&&xlen!=64{return Err("semihost requires XLEN 32 or 64".into())}
        let a=[mask(regs[10],xlen),mask(regs[11],xlen),mask(regs[12],xlen),mask(regs[13],xlen),mask(regs[14],xlen),mask(regs[15],xlen)];
        let nr=mask(regs[17],xlen);
        if nr==93||nr==94 {return Ok(Some(a[0] as i32))}
        let result=(||->Result<u64,i32>{match nr {
            63=>{let fd=a[0] as i32;if !self.valid(fd){return Err(9)}if !mem.allowed(a[1],a[2],2){return Err(EFAULT)}let n=usize::try_from(a[2]).map_err(|_|22)?;let mut b=Vec::new();b.try_reserve_exact(n).map_err(|_|12)?;b.resize(n,0);let count=if let Some(f)=self.fds.get_mut(&fd){f.read(&mut b)}else if fd==0{std::io::stdin().read(&mut b)}else{return Err(9)}.map_err(errno)?;put(mem,a[1],&b[..count])?;Ok(count as u64)},
            64=>{let fd=a[0] as i32;if !self.valid(fd){return Err(9)}let b=bytes(mem,a[1],a[2])?;let n=if let Some(f)=self.fds.get_mut(&fd){f.write(&b)}else if fd==1{let mut out=std::io::stdout().lock();let n=out.write(&b);out.flush().map_err(errno)?;n}else if fd==2{let mut out=std::io::stderr().lock();let n=out.write(&b);out.flush().map_err(errno)?;n}else{return Err(9)}.map_err(errno)?;Ok(n as u64)},
            1024=>self.open(path(mem,a[0])?,a[1],a[2]),
            56=>{let p=self.resolve(a[0] as i32,path(mem,a[1])?)?;self.open(p,a[2],a[3])},
            57=>{let fd=a[0] as i32;if self.fds.remove(&fd).is_some(){Ok(0)}else if fd>=0&&fd<3&&!self.closed[fd as usize]{self.closed[fd as usize]=true;Ok(0)}else{Err(9)}},
            62=>{let fd=a[0] as i32;let missing=if self.valid(fd){29}else{9};let f=self.fds.get_mut(&fd).ok_or(missing)?;let off=signed(a[1],xlen);let pos=match a[2]{0=>{if off<0{return Err(22)}SeekFrom::Start(off as u64)},1=>SeekFrom::Current(off),2=>SeekFrom::End(off),_=>return Err(22)};f.seek(pos).map_err(errno)},
            80=>Self::stat(mem,a[1],self.metadata(a[0] as i32)?),
            1038=>Self::stat(mem,a[1],std::fs::metadata(path(mem,a[0])?).map_err(errno)?),
            79=>{let p=self.resolve(a[0] as i32,path(mem,a[1])?)?;if a[3]&!0x100!=0{return Err(22)}let m=if a[3]&0x100!=0{std::fs::symlink_metadata(p)}else{std::fs::metadata(p)}.map_err(errno)?;Self::stat(mem,a[2],m)},
            214=>{if a[0]==0{return Ok(self.heap_end)}if a[0]<self.heap_base{return Ok(self.heap_end)}if a[0]>self.heap_end {let n=a[0]-self.heap_end;if !mem.allowed(self.heap_end,n,2){return Ok(self.heap_end)}mem.zero(self.heap_end,n).map_err(|_|EFAULT)?;}self.heap_end=a[0];Ok(self.heap_end)},
            169=>{let now=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|5)?;let mut b=Vec::new();let width=(xlen/8) as usize;for v in [now.as_secs(),now.subsec_micros() as u64]{b.extend_from_slice(&v.to_le_bytes()[..width])}if a[0]!=0{put(mem,a[0],&b)?}if a[1]!=0{put(mem,a[1],&[0;8])?}Ok(0)},
            1033=>host::access(&path(mem,a[0])?,a[1]),
            48=>{if a[3]!=0{return Err(22)}host::access(&self.resolve(a[0] as i32,path(mem,a[1])?)?,a[2])},
            2011=>{let b=self.mainvars(a[0],xlen)?;if b.len() as u64>a[1]{return Err(12)}put(mem,a[0],&b)?;Ok(0)},
            _=>Err(38),
        }})();
        regs[10]=mask(match result{Ok(v)=>v,Err(e)=>(-(e as i64)) as u64},xlen);Ok(None)
    }
    fn mainvars(&self,base:u64,xlen:u32)->Result<Vec<u8>,i32>{
        let w=(xlen/8) as usize;let head=(self.args.len()+3).checked_mul(w).ok_or(12)?;let mut b=vec![0u8;head];
        b[..w].copy_from_slice(&(self.args.len() as u64).to_le_bytes()[..w]);
        for (i,s) in self.args.iter().enumerate(){let p=base.checked_add(b.len() as u64).ok_or(EFAULT)?;if xlen==32&&p>u32::MAX as u64{return Err(EFAULT)}b[(i+1)*w..(i+2)*w].copy_from_slice(&p.to_le_bytes()[..w]);b.extend_from_slice(s.as_bytes());b.push(0)}Ok(b)
    }
    pub fn init_process(&mut self,regs:&mut [u64;32],mem:&mut Memory,xlen:u32,args:&[String],env:&[String],stack_top:u64)->Result<(),String>{
        if xlen!=32&&xlen!=64{return Err("process requires XLEN 32 or 64".into())}
        if args.iter().chain(env).any(|s|s.as_bytes().contains(&0)){return Err("argument or environment contains NUL".into())}
        let w=(xlen/8) as usize;let mut sp=stack_top;let mut av=Vec::new();let mut ev=Vec::new();
        for (list,ptrs) in [(env,&mut ev),(args,&mut av)] {for s in list.iter().rev(){sp=sp.checked_sub(s.len() as u64+1).ok_or("process stack underflow")?;let mut b=s.as_bytes().to_vec();b.push(0);put(mem,sp,&b).map_err(|e|format!("process stack errno {e}"))?;ptrs.push(sp)}ptrs.reverse()}
        let mut words=vec![args.len() as u64];words.extend_from_slice(&av);words.push(0);words.extend_from_slice(&ev);words.push(0);
        // AT_PAGESZ and AT_NULL. No invented ELF/program-header addresses.
        words.extend_from_slice(&[6,4096,0,0]);
        sp=sp.checked_sub((words.len()*w) as u64).ok_or("process stack underflow")?&!15;
        if xlen==32 && stack_top>u32::MAX as u64{return Err("RV32 stack address exceeds XLEN".into())}
        let mut b=Vec::with_capacity(words.len()*w);for word in words{b.extend_from_slice(&word.to_le_bytes()[..w])}put(mem,sp,&b).map_err(|e|format!("process stack errno {e}"))?;
        regs[2]=sp;regs[10]=args.len() as u64;regs[11]=sp+w as u64;regs[12]=sp+((args.len()+2)*w) as u64;self.args=args.to_vec();Ok(())
    }
}

// Only this module touches libc ABI; never pass a guest pointer to the host.
mod host {
    use std::path::Path;
    use std::os::unix::ffi::OsStrExt;
    extern "C" {#[link_name="access"] fn libc_access(path:*const std::os::raw::c_char,mode:std::os::raw::c_int)->std::os::raw::c_int;}
    pub fn access(p:&Path,mode:u64)->Result<u64,i32>{if mode&!7!=0{return Err(22)}let p=std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_|22)?;let r=unsafe{libc_access(p.as_ptr(),mode as i32)};if r<0{Err(super::errno(std::io::Error::last_os_error()))}else{Ok(0)}}
}
