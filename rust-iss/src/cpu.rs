//! Integer RISC-V execution, privileged state, and physical protection.
use crate::{config::CpuConfig, cov::Cov, memory::Memory, semihost::Semihost};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow { Next, Trap(u64,u64) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit { Running, Halt, Stop(&'static str), Terminate, Ecall }
pub struct Machine {
 pub x:[u64;32], pub pc:u64, pub mstatus:u64, pub misa:u64, pub mie:u64, pub mtvec:u64,
 pub mscratch:u64, pub mepc:u64, pub mcause:u64, pub mtval:u64, pub mip:u64,
 pub counter:u64, pub mem:Memory, pub tohost:Option<u64>, pub instret:u64,
 pub finish_after:Option<u64>, pub finish_time:Option<f64>, pub sig_armed:bool,
 pub sig_lo:u64,pub sig_hi:u64,pub sig_writes:u64,pub cov:Option<Cov>,
 pub cov_lo:Option<u64>,pub cov_hi:Option<u64>,pub cov_on:bool,pub cov_counted:u64,
 pub halt_pc:Option<u64>,
 pub hist:Option<std::collections::BTreeMap<u64,u64>>,pub trace:Option<std::fs::File>,
 pub addr_mask:u64,pub stop_pc:Option<u64>,pub stop_opcode:Option<u32>,pub stop_terminate:Option<u64>,
 pub ecall_reg:Option<usize>,pub ecall_pass:bool,pub exit:Exit,pub config:CpuConfig,
 pub semihost:Option<Semihost>,pub privilege:u8,
 pub custom_control:bool, pub logfile:Option<std::fs::File>, pub custom_exit_pc:Option<u64>,
 medeleg:u64,mideleg:u64,stvec:u64,sscratch:u64,sepc:u64,scause:u64,stval:u64,satp:u64,
 mcounteren:u64,scounteren:u64,mcountinhibit:u64,pmpcfg:[u8;64],pmpaddr:[u64;64],reservation:Option<(u64,u32)>,
}
fn sext(v:u64,b:u32)->u64 { ((v << (64-b)) as i64 >> (64-b)) as u64 }
impl Machine {
 pub fn new(mem:Memory,pc:u64,tohost:Option<u64>,config:CpuConfig)->Self {
 let misa=config.extensions | if config.xlen==32 {1<<30} else {2<<62}; let mtvec=config.mtvec;
 Self{custom_control:false,logfile:None,custom_exit_pc:None,x:[0;32],pc,mstatus:0,misa,mie:0,mtvec,mscratch:0,mepc:0,mcause:0,mtval:0,mip:0,counter:0,mem,tohost,instret:0,finish_after:None,finish_time:None,sig_armed:false,sig_lo:0,sig_hi:0,sig_writes:0,cov:None,cov_lo:None,cov_hi:None,cov_on:false,cov_counted:0,halt_pc:None,hist:std::env::var_os("RUSTISS_PCDUMP").map(|_|Default::default()),trace:std::env::var("RUSTISS_TRACE").ok().and_then(|p|std::fs::File::create(p).ok()),addr_mask:u64::MAX,stop_pc:None,stop_opcode:None,stop_terminate:None,ecall_reg:None,ecall_pass:false,exit:Exit::Running,config,semihost:None,privilege:3,medeleg:0,mideleg:0,stvec:0,sscratch:0,sepc:0,scause:0,stval:0,satp:0,mcounteren:0,scounteren:0,mcountinhibit:0,pmpcfg:[0;64],pmpaddr:[0;64],reservation:None}
 }
 fn mask(&self,v:u64)->u64 {if self.config.xlen==32 {v as u32 as u64}else{v}}
 fn signed(&self,v:u64)->i64 {if self.config.xlen==32 {v as i32 as i64}else{v as i64}}
 fn ext(&self,c:u8)->bool {self.misa&(1u64<<(c-b'A'))!=0}
 fn set_reg(&mut self,r:usize,v:u64){if r!=0 {self.x[r]=self.mask(v)}}
 fn effective_pmp_addr(&self,i:usize)->u64 {let g=self.config.pmp_grain.min(29);let raw=self.pmpaddr[i];if self.pmpcfg[i]&0x18!=0x18{raw&(!0u64<<g)}else if g>=2{raw|((1u64<<(g-1))-1)}else{raw}}
 pub fn watch_signature(&mut self,lo:u64,bytes:u64){self.sig_armed=bytes!=0;self.sig_lo=lo;self.sig_hi=lo.wrapping_add(bytes.saturating_sub(1));self.sig_writes=0;}
 fn effective_priv(&self,access:u8)->u8 {if access!=2 && self.privilege==3 && self.mstatus&(1<<17)!=0 {((self.mstatus>>11)&3)as u8}else{self.privilege}}
 fn pmp(&self,a:u64,n:u32,access:u8,p:u8)->bool {
 let mut lower=0u64;
 for i in 0..self.config.pmp_registers.min(64) as usize {
 let cfg=self.pmpcfg[i];let raw=self.effective_pmp_addr(i);
 if cfg&0x18==8 {lower=if i==0{0}else{(self.pmpaddr[i-1]&(!0u64<<self.config.pmp_grain.min(29)))<<2};}
 let (lo,hi)=match (cfg>>3)&3 {0=>{lower=raw<<2;continue},1=>(lower,raw<<2),2=>(raw<<2,(raw<<2).saturating_add(4)),_=>{let ones=raw.trailing_ones();let size=1u64.checked_shl(ones+3).unwrap_or(0);let base=(raw & !((1u64.checked_shl(ones+1).unwrap_or(0)).wrapping_sub(1)))<<2;(base,if size==0 {u64::MAX}else{base.saturating_add(size)})}};
 lower=raw<<2;let end=a.saturating_add(n as u64);if a<hi && end>lo {if a<lo || end>hi{return false}if p==3 && cfg&128==0{return true}return cfg&(1<<access)!=0}
 } p==3 || self.config.pmp_registers==0
 }
 fn translate(&mut self,va:u64,access:u8)->Result<u64,u64>{
 let p=self.effective_priv(access);let fault=if access==2{12}else if access==1{15}else{13};
 let mode=if self.config.xlen==32 {self.satp>>31}else{self.satp>>60};
 if p==3||mode==0{return Ok(va&self.addr_mask)}
 let (levels,bits,ps,ppnmask)=match (self.config.xlen,mode){(32,1)=>(2u32,10u32,4u32,(1u64<<22)-1),(64,8)=>(3,9,8,(1u64<<44)-1),(64,9)=>(4,9,8,(1u64<<44)-1),_=>return Err(fault)};
 let vabits=12+levels*bits;if self.config.xlen==64 && sext(va&((1u64<<vabits)-1),vabits)!=va{return Err(fault)}
 let mut table=(self.satp&ppnmask)<<12;
 for level in (0..levels).rev(){let index=(va>>(12+level*bits))&((1<<bits)-1);let pa=table+index*ps as u64;
 if !self.pmp(pa,ps,0,1){return Err(if access==2{1}else if access==1{7}else{5})}
 let mut pte=self.mem.read(pa,ps).ok_or(if access==2{1u64}else if access==1{7u64}else{5u64})?;
 if pte&1==0 || pte&6==4 || (ps==8 && pte>>54!=0){return Err(fault)}
 if pte&10!=0 {let user=pte&16!=0;if (p==0&&!user)||(p==1&&user&&(access==2||self.mstatus&(1<<18)==0)){return Err(fault)}
 let allowed=match access{2=>pte&8!=0,1=>pte&4!=0,_=>pte&2!=0 || (pte&8!=0&&self.mstatus&(1<<19)!=0)};if !allowed{return Err(fault)}
 let ppn=(pte>>10)&ppnmask;let lowbits=level*bits;if lowbits>0&&ppn&((1<<lowbits)-1)!=0{return Err(fault)}
 let need=64|if access==1{128}else{0};if pte&need!=need {pte|=need;if !self.pmp(pa,ps,1,1)||!self.mem.write(pa,ps,pte){return Err(fault)}}
 let lowmask=(1u64<<(12+lowbits))-1;return Ok((((ppn<<12)&!lowmask)|(va&lowmask))&self.addr_mask)
 }if pte&0xd0!=0{return Err(fault)}table=((pte>>10)&ppnmask)<<12;
 }Err(fault)
 }
 fn load_access(&mut self,a:u64,n:u32,access:u8)->Result<u64,(u64,u64)>{
 if a%n as u64!=0&&(access==2||!self.config.unaligned){return Err((if access==2{0}else{4},a))}
 let mut v=0;for i in 0..n {let va=self.mask(a.wrapping_add(i as u64));let pa=self.translate(va,access).map_err(|c|(c,a))?;let chunk=if i==0||va&4095==0{(n-i).min((4096-(va&4095))as u32)}else{1};if !self.pmp(pa,chunk,access,self.effective_priv(access)){return Err((if access==2{1}else{5},a))}let byte=if access==2{self.mem.fetch(pa,1)}else{self.mem.read(pa,1)};v|=byte.ok_or((if access==2{1}else{5},a))?<<(8*i);}Ok(v)
 }
 fn store_access(&mut self,a:u64,n:u32,v:u64)->Result<(),(u64,u64)>{
 if a%n as u64!=0&&!self.config.unaligned{return Err((6,a))}
 let mut physical=[0u64;8];for i in 0..n {let va=self.mask(a.wrapping_add(i as u64));let pa=self.translate(va,1).map_err(|c|(c,a))?;let chunk=if i==0||va&4095==0{(n-i).min((4096-(va&4095))as u32)}else{1};if !self.pmp(pa,chunk,1,self.effective_priv(1))||!self.mem.allowed(pa,1,2){return Err((7,a))}physical[i as usize]=pa;}
 for i in 0..n {if !self.mem.write(physical[i as usize],1,v>>(8*i)){return Err((7,a))}}
 self.reservation=None;if self.sig_armed&&a<=self.sig_hi&&a.saturating_add(n as u64-1)>=self.sig_lo{self.sig_writes+=1}if Some(a)==self.tohost{self.exit=Exit::Halt}Ok(())
 }
 fn time_ticks(&self)->u64 {(self.counter as f64*self.config.mtime_hz/(self.config.mips*1_000_000.0))as u64}
 fn csr_read(&self,a:u32)->Option<u64>{
 if matches!(a,0xc00|0xc80)&&self.config.cycle_undefined || matches!(a,0xb00|0xb80)&&self.config.mcycle_undefined || matches!(a,0xc01|0xc81)&&self.config.time_undefined || matches!(a,0xc02|0xc82)&&self.config.instret_undefined || matches!(a,0xb02|0xb82)&&self.config.minstret_undefined{return None}
 Some(match a {
 0x100=>self.mstatus&0x8000_0003_000d_e133,0x104=>self.mie&self.mideleg,0x105=>self.stvec,0x106=>self.scounteren,0x140=>self.sscratch,0x141=>self.sepc,0x142=>self.scause,0x143=>self.stval,0x144=>self.mip&self.mideleg,0x180=>self.satp,
 0x300=>self.mstatus,0x301=>self.misa,0x302=>self.medeleg,0x303=>self.mideleg,0x304=>self.mie,0x305=>self.mtvec,0x306=>self.mcounteren,0x320=>self.mcountinhibit,0x340=>self.mscratch,0x341=>self.mepc,0x342=>self.mcause,0x343=>self.mtval,0x344=>self.mip,
 0xb00|0xc00=>self.mask(self.counter),0xc01=>self.mask(self.time_ticks()),0xb02|0xc02=>self.mask(self.instret),0xb80|0xc80 if self.config.xlen==32=>self.counter>>32,0xc81 if self.config.xlen==32=>self.time_ticks()>>32,0xb82|0xc82 if self.config.xlen==32=>self.instret>>32,
 0xf11|0xf12|0xf13|0xf14=>0,
 0x3a0..=0x3af=>{let stride=if self.config.xlen==32{4}else{8};if stride==8&&a&1!=0{return None}let first=(a-0x3a0)as usize*4;if first>=self.config.pmp_registers as usize{return None}let mut v=0;for j in 0..stride{v|=(self.pmpcfg[first+j]as u64)<<(j*8)}v},
 0x3b0..=0x3ef=>{let i=(a-0x3b0)as usize;if i>=self.config.pmp_registers as usize{return None}self.effective_pmp_addr(i)},_=>return None})}
 fn csr_write(&mut self,a:u32,v:u64)->bool{match a{
 0x100=>{let mask=0x000d_e133;self.mstatus=(self.mstatus&!mask)|(v&mask)},0x104=>self.mie=(self.mie&!self.mideleg)|(v&self.mideleg),0x105=>self.stvec=v&!2,0x106=>self.scounteren=v&u64::from(self.config.counteren_mask&!self.config.scounteren_zero_mask),0x140=>self.sscratch=v,0x141=>self.sepc=v&!1,0x142=>self.scause=v,0x143=>self.stval=v,0x144=>self.mip=(self.mip&!2)|(v&self.mideleg&2),
 0x180=>{let mode=if self.config.xlen==32{v>>31}else{v>>60};if mode==0||(self.config.xlen==32&&mode==1)||(self.config.xlen==64&&(mode==8||mode==9)){self.satp=v}},
 0x300=>{let mask=0x0000_003f_007f_ffbb;self.mstatus=(self.mstatus&!mask)|(v&mask);if (self.mstatus>>11)&3==2{self.mstatus&=!(3<<11)}},
 0x301=>{},0x302=>self.medeleg=v&0xb3ff,0x303=>self.mideleg=v&0x222,0x304=>self.mie=v&0xaaa,0x305=>{if !self.config.mtvec_is_ro{self.mtvec=(self.mtvec&!self.config.mtvec_mask)|(v&self.config.mtvec_mask);self.mtvec&=!2;let align=self.config.tvec_align;if align>0&&align<64{self.mtvec=(self.mtvec&3)|(self.mtvec&(!0u64<<align));}}},0x306=>self.mcounteren=v&u64::from(self.config.counteren_mask),0x320=>self.mcountinhibit=v&5&!u64::from(self.config.noinhibit_mask),
 0x340=>self.mscratch=v,0x341=>self.mepc=v&!1,0x342=>self.mcause=v,0x343=>self.mtval=v,0x344=>self.mip=(self.mip&!0x222)|(v&0x222),
 0xb00=>self.counter=if self.config.xlen==32{(self.counter&!0xffff_ffff)|v}else{v},0xb02=>self.instret=if self.config.xlen==32{(self.instret&!0xffff_ffff)|v}else{v},0xb80 if self.config.xlen==32=>self.counter=(self.counter&0xffff_ffff)|(v<<32),0xb82 if self.config.xlen==32=>self.instret=(self.instret&0xffff_ffff)|(v<<32),
 0x3a0..=0x3af=>{if self.config.pmp_undefined{return false}let stride=if self.config.xlen==32{4}else{8};if stride==8&&a&1!=0{return false}let first=(a-0x3a0)as usize*4;if first>=self.config.pmp_registers as usize{return false}for j in 0..stride {if first+j<self.config.pmp_registers as usize&&self.pmpcfg[first+j]&128==0 {let mut c=(v>>(j*8))as u8&0x9f;if c&3==2{c&=!2}if self.config.pmp_grain>0&&c&0x18==0x10{c&=!0x10}self.pmpcfg[first+j]=c}}},
 0x3b0..=0x3ef=>{let i=(a-0x3b0)as usize;if i>=self.config.pmp_registers as usize{return false}if self.pmpcfg[i]&128==0 && !(i+1<64&&self.pmpcfg[i+1]&0x98==0x88){self.pmpaddr[i]=v&if self.config.xlen==32{0xffff_ffff}else{(1<<54)-1}}},_=>return false}true}
 fn take_trap(&mut self,cause:u64,tval:u64)->Result<(),String>{let interrupt=cause>>(self.config.xlen-1)!=0;let c=cause&!(1<<(self.config.xlen-1));let delegated=self.privilege!=3&&self.config.supervisor_mode&&c<64&&(if interrupt{self.mideleg}else{self.medeleg})&(1<<c)!=0;let vec;
 if delegated {self.sepc=self.pc;self.scause=cause;self.stval=tval;self.mstatus=(self.mstatus&!0x122)|((self.mstatus&2)<<4)|((self.privilege as u64)<<8);self.privilege=1;vec=self.stvec;}else{self.mepc=self.pc;self.mcause=cause;self.mtval=tval;self.mstatus=(self.mstatus&!0x1888)|((self.mstatus&8)<<4)|((self.privilege as u64)<<11);self.privilege=3;vec=self.mtvec;}
 self.pc=self.mask((vec&!3)+if interrupt&&vec&3==1{4*c}else{0});self.reservation=None;Ok(())}
 pub fn run(&mut self)->Result<(),String>{let mut elapsed=0u64;loop{
 if self.exit!=Exit::Running{return Ok(())}if self.finish_after.is_some_and(|v|self.instret>=v){self.exit=Exit::Stop("instruction count");return Ok(())}if self.finish_time.is_some_and(|v|elapsed as f64>=v*self.config.mips*1_000_000.0){self.exit=Exit::Stop("simulation time");return Ok(())}elapsed=elapsed.wrapping_add(1);
 if Some(self.pc)==self.stop_pc{self.stop_simulation("address match");return Ok(())}if Some(self.pc)==self.stop_terminate{println!("Info (EXC_FT) Intercept 'terminate'.");self.exit=Exit::Terminate;if self.ecall_reg.is_some(){self.print_verdict()}return Ok(())}
 let pending=self.mie&self.mip;let mut irq=None;for c in [11,3,7,9,1,5]{if pending&(1<<c)!=0 {let delegated=self.mideleg&(1<<c)!=0;let enabled=if delegated{self.privilege<1||(self.privilege==1&&self.mstatus&2!=0)}else{self.privilege<3||self.mstatus&8!=0};if enabled{irq=Some(c);break}}}if let Some(c)=irq{self.take_trap((1<<(self.config.xlen-1))|c,0)?;continue}
 let alignment=if self.ext(b'C'){2}else{4};if self.pc%alignment!=0{self.take_trap(0,self.pc)?;continue}
 let low=match self.load_access(self.pc,2,2){Ok(v)=>v as u32,Err((c,v))=>{self.take_trap(c,v)?;continue}};
 let (ins,len)=if low&3!=3{(low,2)}else{let hi=match self.load_access(self.mask(self.pc.wrapping_add(2)),2,2){Ok(v)=>v as u32,Err((c,v))=>{self.take_trap(c,v)?;continue}};(low|(hi<<16),4)};
 if self.custom_control&&self.custom_exit_pc.is_some_and(|point|point>=self.pc&&point<self.pc.saturating_add(len)){self.exit=Exit::Terminate;return Ok(())}
 if self.custom_control&&ins==0x0005200b{if self.x[10]==0{self.exit=Exit::Halt;return Ok(())}let byte=[self.x[10]as u8];std::io::Write::write_all(&mut std::io::stdout(),&byte).map_err(|e|format!("customControl stdout: {e}"))?;if let Some(file)=self.logfile.as_mut(){std::io::Write::write_all(file,&byte).map_err(|e|format!("customControl logfile: {e}"))?;}self.pc=self.mask(self.pc.wrapping_add(4));if self.mcountinhibit&1==0{self.counter=self.counter.wrapping_add(1)}if self.mcountinhibit&4==0{self.instret=self.instret.wrapping_add(1)}continue}
 if self.stop_opcode==Some(ins){self.stop_simulation("opcode match");return Ok(())}
 if self.mcountinhibit&1==0{self.counter=self.counter.wrapping_add(1)}
 if let Some(h)=self.hist.as_mut(){*h.entry(self.pc).or_insert(0)+=1}if let Some(f)=self.trace.as_mut(){let _=std::io::Write::write_fmt(f,format_args!("{:08x}\n",self.pc));}
 if Some(self.pc)==self.cov_lo{self.cov_on=true}let cov_at_hi=Some(self.pc)==self.cov_hi;
 let decoded=if len==2 {if self.ext(b'C'){self.decompress(ins as u16)}else{None}}else{Some(ins)};
 let cover=if self.cov_on&&self.cov.is_some(){decoded.and_then(|i|self.decode_cover(i)).and_then(|(name,operands)|if len==2{self.compressed_name(ins as u16).map(|name|(name,operands))}else{Some((name,operands))})}else{None};
 // The original ends the run on entry to `write_tohost`: the signature dump is
 // driven from that callback, so the function body never executes. The
 // instruction is still counted, traced and attributed to coverage, using the
 // register state it would have executed with.
 if self.halt_pc==Some(self.pc){
  if let Some((name,mut operands))=cover{operands.rd_val=self.would_write(ins).unwrap_or(self.x[operands.rd]);if let Some(c)=self.cov.as_mut(){if c.record_named(name,&operands){self.cov_counted+=1}}}
  self.exit=Exit::Halt;return Ok(())
 }
 let flow=if let Some(i)=decoded{self.exec(i,len)?}else{Flow::Trap(2,ins as u64)};
 match flow{Flow::Trap(c,v)=>self.take_trap(c,if c==2{ins as u64}else{v})?,Flow::Next=>{if self.mcountinhibit&4==0{self.instret=self.instret.wrapping_add(1)}}}
 if self.exit==Exit::Running {if let Some((name,mut operands))=cover{operands.rd_val=self.x[operands.rd];if let Some(c)=self.cov.as_mut(){if c.record_named(name,&operands){self.cov_counted+=1}}}}
 // The instruction at the finish symbol is part of the window, exactly as the
 // original model counts it; the window closes after it executes.
 if cov_at_hi{self.cov_on=false}
 }}
 /// The value a not-yet-executed instruction would write to `rd`. The original
 /// attributes coverage for the instruction it stops on (`write_tohost` entry)
 /// from that write, not from the register's previous contents; its prologue is
 /// an `auipc`, whose result is available without executing anything.
 fn would_write(&self,ins:u32)->Option<u64>{match ins&127{0x17=>Some(self.mask(self.pc.wrapping_add(sext((ins&0xfffff000)as u64,32)))),0x37=>Some(self.mask(sext((ins&0xfffff000)as u64,32))),_=>None}}
 fn stop_simulation(&mut self,reason:&'static str){println!("Info (EXC_FS) {reason}: Stopping at 0x{:x}",self.pc);self.exit=Exit::Stop(reason);if self.ecall_reg.is_some(){self.print_verdict()}}
 fn print_verdict(&self){println!("{}",if self.ecall_pass{"Test PASSED"}else{"Test FAILED"})}
 fn compressed_name(&self,h:u16)->Option<&'static str>{let c=h as u32;Some(match(c&3,c>>13){(0,0)=>"c.addi4spn",(0,2)=>"c.lw",(0,3)=>"c.ld",(0,6)=>"c.sw",(0,7)=>"c.sd",(1,0)=>if c&0xfffc==0{"c.nop"}else{"c.addi"},(1,1)=>if self.config.xlen==32{"c.jal"}else{"c.addiw"},(1,2)=>"c.li",(1,3)=>if (c>>7)&31==2{"c.addi16sp"}else{"c.lui"},(1,4)=>match(c>>10)&3{0=>"c.srli",1=>"c.srai",2=>"c.andi",_=>if c&0x1000==0{["c.sub","c.xor","c.or","c.and"][((c>>5)&3)as usize]}else{["c.subw","c.addw"][((c>>5)&1)as usize]}},(1,5)=>"c.j",(1,6)=>"c.beqz",(1,7)=>"c.bnez",(2,0)=>"c.slli",(2,2)=>"c.lwsp",(2,3)=>"c.ldsp",(2,4)=>if c&0x1000==0{if c&0x7c==0{"c.jr"}else{"c.mv"}}else if c&0x7c==0{if c&0xf80==0{"c.ebreak"}else{"c.jalr"}}else{"c.add"},(2,6)=>"c.swsp",(2,7)=>"c.sdsp",_=>return None})}
 fn decode_cover(&self,i:u32)->Option<(&'static str,crate::cov::Operands64)>{
 let op=i&127;let f=(i>>12)&7;let top=i>>25;let rd=((i>>7)&31)as usize;let rs1=((i>>15)&31)as usize;let rs2=((i>>20)&31)as usize;let mut imm=sext((i>>20)as u64,12)as i64;
 if op==0x2f{let d=f==3;let name=match(i>>27,d){(2,false)=>"lr.w",(2,true)=>"lr.d",(3,false)=>"sc.w",(3,true)=>"sc.d",(0,false)=>"amoadd.w",(0,true)=>"amoadd.d",(1,false)=>"amoswap.w",(1,true)=>"amoswap.d",(4,false)=>"amoxor.w",(4,true)=>"amoxor.d",(8,false)=>"amoor.w",(8,true)=>"amoor.d",(12,false)=>"amoand.w",(12,true)=>"amoand.d",(16,false)=>"amomin.w",(16,true)=>"amomin.d",(20,false)=>"amomax.w",(20,true)=>"amomax.d",(24,false)=>"amominu.w",(24,true)=>"amominu.d",(28,false)=>"amomaxu.w",(28,true)=>"amomaxu.d",_=>return None};return Some((name,crate::cov::Operands64{rd,rs1,rs2,imm:0,offset:0,rd_val:0,rs1_val:self.x[rs1],rs2_val:self.x[rs2]}))}
 let name=match op{0x37=>"lui",0x17=>"auipc",0x6f=>"jal",0x67=>"jalr",0x63=>{imm=sext((((i>>31)<<12)|(((i>>7)&1)<<11)|(((i>>25)&63)<<5)|(((i>>8)&15)<<1))as u64,13)as i64;match f{0=>"beq",1=>"bne",4=>"blt",5=>"bge",6=>"bltu",7=>"bgeu",_=>return None}},0x03=>match f{0=>"lb",1=>"lh",2=>"lw",3=>"ld",4=>"lbu",5=>"lhu",6=>"lwu",_=>return None},0x23=>{imm=sext((((i>>25)<<5)|((i>>7)&31))as u64,12)as i64;match f{0=>"sb",1=>"sh",2=>"sw",3=>"sd",_=>return None}},0x13=>match f{0=>"addi",1=>{imm=((i>>20)&(self.config.xlen-1))as i64;"slli"},2=>"slti",3=>"sltiu",4=>"xori",5=>{imm=((i>>20)&(self.config.xlen-1))as i64;if i&0x40000000!=0{"srai"}else{"srli"}},6=>"ori",7=>"andi",_=>return None},0x1b=>match f{0=>"addiw",1=>"slliw",5=>if top==32{"sraiw"}else{"srliw"},_=>return None},0x33|0x3b=>{imm=0;if top==1{if op==0x33{["mul","mulh","mulhsu","mulhu","div","divu","rem","remu"][f as usize]}else{match f{0=>"mulw",4=>"divw",5=>"divuw",6=>"remw",7=>"remuw",_=>return None}}}else if op==0x3b{match(f,top){(0,0)=>"addw",(0,32)=>"subw",(1,0)=>"sllw",(5,0)=>"srlw",(5,32)=>"sraw",_=>return None}}else{match(f,top){(0,0)=>"add",(0,32)=>"sub",(1,0)=>"sll",(2,0)=>"slt",(3,0)=>"sltu",(4,0)=>"xor",(5,0)=>"srl",(5,32)=>"sra",(6,0)=>"or",(7,0)=>"and",_=>return None}}},0x0f=>if f==0{"fence"}else{"fence.i"},0x73=>if f!=0{match f{1=>"csrrw",2=>"csrrs",3=>"csrrc",5=>"csrrwi",6=>"csrrsi",7=>"csrrci",_=>return None}}else{match i{0x73=>"ecall",0x00100073=>"ebreak",0x30200073=>"mret",0x10200073=>"sret",0x10500073=>"wfi",_=>"sfence.vma"}},_=>return None};
 Some((name,crate::cov::Operands64{rd,rs1,rs2,imm,offset:imm,rd_val:0,rs1_val:self.x[rs1],rs2_val:self.x[rs2]}))
 }
 fn exec(&mut self,ins:u32,len:u64)->Result<Flow,String>{
 let op=ins&127;let rd=((ins>>7)&31)as usize;let f=(ins>>12)&7;let r1=((ins>>15)&31)as usize;let r2=((ins>>20)&31)as usize;let f7=ins>>25;let a=self.x[r1];let b=self.x[r2];let im=sext((ins>>20)as u64,12);let pc=self.pc;let next=self.mask(pc.wrapping_add(len));let illegal=Flow::Trap(2,ins as u64);let mut target=next;let mut result=None;
 if self.ext(b'E') {let uses_rd=!matches!(op,0x23|0x63|0x0f);let uses_rs1=!matches!(op,0x37|0x17|0x6f|0x0f)&&!(op==0x73&&(f==0||f&4!=0));let uses_rs2=matches!(op,0x23|0x63|0x33|0x3b|0x2f);if uses_rd&&rd>=16||uses_rs1&&r1>=16||uses_rs2&&r2>=16{return Ok(illegal)}}
 match op{
 0x37=>result=Some(sext((ins&0xfffff000)as u64,32)),0x17=>result=Some(pc.wrapping_add(sext((ins&0xfffff000)as u64,32))),
 0x6f=>{let off=sext((((ins>>31)<<20)|(((ins>>12)&255)<<12)|(((ins>>20)&1)<<11)|(((ins>>21)&1023)<<1))as u64,21);target=self.mask(pc.wrapping_add(off));result=Some(next)},
 0x67 if f==0=>{target=self.mask(a.wrapping_add(im))&!1;result=Some(next)},
 0x63=>{let taken=match f{0=>a==b,1=>a!=b,4=>self.signed(a)<self.signed(b),5=>self.signed(a)>=self.signed(b),6=>a<b,7=>a>=b,_=>return Ok(illegal)};if taken{let off=sext((((ins>>31)<<12)|(((ins>>7)&1)<<11)|(((ins>>25)&63)<<5)|(((ins>>8)&15)<<1))as u64,13);target=self.mask(pc.wrapping_add(off))}},
 0x03=>{let(n,s)=match f{0=>(1,true),1=>(2,true),2=>(4,true),3 if self.config.xlen==64=>(8,true),4=>(1,false),5=>(2,false),6 if self.config.xlen==64=>(4,false),_=>return Ok(illegal)};match self.load_access(self.mask(a.wrapping_add(im)),n,0){Ok(v)=>result=Some(if s{sext(v,n*8)}else{v}),Err((c,v))=>return Ok(Flow::Trap(c,v))}},
 0x23=>{let n=match f{0=>1,1=>2,2=>4,3 if self.config.xlen==64=>8,_=>return Ok(illegal)};let off=sext((((ins>>25)<<5)|((ins>>7)&31))as u64,12);if let Err((c,v))=self.store_access(self.mask(a.wrapping_add(off)),n,b){return Ok(Flow::Trap(c,v))}},
 0x13|0x1b=>{let word=op==0x1b;if word&&self.config.xlen!=64{return Ok(illegal)}let width=if word{32}else{self.config.xlen};let sh=(ins>>20)&(width-1);let top=ins>>(20+if width==64{6}else{5});let val=match f{0=>a.wrapping_add(im),2 if !word=>(self.signed(a)<self.signed(im))as u64,3 if !word=>(a<self.mask(im))as u64,4 if !word=>a^im,6 if !word=>a|im,7 if !word=>a&im,1 if top==0=>a<<sh,5 if top==0=>if word{(a as u32>>sh)as u64}else{a>>sh},5 if top==0x20>>if width==64{1}else{0}=>if word{((a as i32)>>sh)as u64}else{(self.signed(a)>>sh)as u64},_=>return Ok(illegal)};result=Some(if word{sext(val,32)}else{val})},
 0x33|0x3b=>{let word=op==0x3b;if word&&self.config.xlen!=64{return Ok(illegal)}let width=if word{32}else{self.config.xlen};let aa=if width==32{a as u32 as u64}else{a};let bb=if width==32{b as u32 as u64}else{b};let sa=if width==32{aa as i32 as i64}else{aa as i64};let sb=if width==32{bb as i32 as i64}else{bb as i64};let sh=(bb as u32)&(width-1);
 let val=if f7==1 {if !self.ext(b'M'){return Ok(illegal)}match f{0=>aa.wrapping_mul(bb),1 if !word=>(((sa as i128)*(sb as i128))>>width)as u64,2 if !word=>(((sa as i128)*(bb as i128))>>width)as u64,3 if !word=>(((aa as u128)*(bb as u128))>>width)as u64,4=>if bb==0{u64::MAX}else{sa.wrapping_div(sb)as u64},5=>if bb==0{u64::MAX}else{aa/bb},6=>if bb==0{aa}else{sa.wrapping_rem(sb)as u64},7=>if bb==0{aa}else{aa%bb},_=>return Ok(illegal)}}else{match(f,f7){(0,0)=>aa.wrapping_add(bb),(0,32)=>aa.wrapping_sub(bb),(1,0)=>aa<<sh,(2,0)if !word=>(sa<sb)as u64,(3,0)if !word=>(aa<bb)as u64,(4,0)if !word=>aa^bb,(5,0)=>aa>>sh,(5,32)=>(sa>>sh)as u64,(6,0)if !word=>aa|bb,(7,0)if !word=>aa&bb,_=>return Ok(illegal)}};result=Some(if word{sext(val,32)}else{val})},
 0x2f=>{if !self.ext(b'A'){return Ok(illegal)}let n=match f{2=>4,3 if self.config.xlen==64=>8,_=>return Ok(illegal)};let kind=ins>>27;if a%n as u64!=0{return Ok(Flow::Trap(if kind==2{4}else{6},a))}if kind==2&&r2!=0{return Ok(illegal)}
 if kind==3{let ok=self.reservation==Some((a,n));self.reservation=None;let pa=match self.translate(a,1){Ok(v)=>v,Err(c)=>return Ok(Flow::Trap(c,a))};if !self.pmp(pa,n,1,self.effective_priv(1)){return Ok(Flow::Trap(7,a))}if ok{if let Err((c,v))=self.store_access(a,n,b){return Ok(Flow::Trap(c,v))}}result=Some((!ok)as u64)}else{let old=match self.load_access(a,n,0){Ok(v)=>v,Err((c,v))=>return Ok(Flow::Trap(if kind==2{c}else{if c==13{15}else if c==5{7}else{c}},v))};if kind==2{self.reservation=Some((a,n))}else{let signed=|v:u64|if n==4{v as i32 as i64}else{v as i64};let val=match kind{0=>old.wrapping_add(b),1=>b,4=>old^b,8=>old|b,12=>old&b,16=>if signed(old)<signed(b){old}else{b},20=>if signed(old)>signed(b){old}else{b},24=>old.min(if n==4{b as u32 as u64}else{b}),28=>old.max(if n==4{b as u32 as u64}else{b}),_=>return Ok(illegal)};if let Err((c,v))=self.store_access(a,n,val){return Ok(Flow::Trap(c,v))}}result=Some(if n==4{sext(old,32)}else{old})}},
 0x0f=>{if f>1{return Ok(illegal)}},
 0x73=>{if f==0{match ins{
 0x00000073=>{if let Some(r)=self.ecall_reg{self.ecall_pass=self.x[r]==1;self.print_verdict();self.exit=Exit::Ecall}else if let Some(handler)=self.semihost.as_mut(){if let Some(status)=handler.handle(&mut self.x,&mut self.mem,self.config.xlen)?{self.ecall_pass=status==0;self.exit=Exit::Ecall}}else{return Ok(Flow::Trap(8+self.privilege as u64,0))}},0x00100073=>return Ok(Flow::Trap(3,pc)),
 0x30200073 if self.privilege==3=>{let p=((self.mstatus>>11)&3)as u8;if p==2||(p==1&&!self.config.supervisor_mode)||(p==0&&!self.config.user_mode){return Ok(illegal)}self.privilege=p;self.mstatus=(self.mstatus&!0x1888)|((self.mstatus>>4)&8)|128;if p!=3{self.mstatus&=!(1<<17)}target=self.mepc},
 0x10200073 if self.config.supervisor_mode&&self.privilege>=1=>{if self.privilege==1&&self.mstatus&(1<<22)!=0{return Ok(illegal)}self.privilege=((self.mstatus>>8)&1)as u8;self.mstatus=(self.mstatus&!0x122)|((self.mstatus>>4)&2)|32;self.mstatus&=!(1<<17);target=self.sepc},
 0x10500073=>{if self.privilege==0||(self.privilege!=3&&self.mstatus&(1<<21)!=0){return Ok(illegal)}if !self.config.wfi_is_nop&&self.mip&self.mie==0{return Err(format!("WFI at 0x{pc:x} is waiting with no external interrupt source"))}},
 _ if ins&0xfe007fff==0x12000073&&self.config.supervisor_mode&&self.privilege>=1=>{if self.privilege==1&&self.mstatus&(1<<20)!=0{return Ok(illegal)}},_=>return Ok(illegal)}}else{
 let csr=ins>>20;let required=((csr>>8)&3)as u8;if self.privilege<required||(required==1&&!self.config.supervisor_mode)||(csr==0x180&&self.privilege==1&&self.mstatus&(1<<20)!=0){return Ok(illegal)}
 if (0xc00..=0xc1f).contains(&csr)||(0xc80..=0xc9f).contains(&csr){let bit=csr&31;if self.privilege<3&&self.mcounteren&(1<<bit)==0||self.privilege==0&&self.scounteren&(1<<bit)==0{return Ok(illegal)}}
 let mode=f&3;if mode==0{return Ok(illegal)}let src=if f&4!=0{r1 as u64}else{a};let write=mode==1||r1!=0;let old=match self.csr_read(csr){Some(v)=>v,None=>return Ok(illegal)};if write{if csr>>10==3{return Ok(illegal)}let val=match mode{1=>src,2=>old|src,_=>old&!src};if !self.csr_write(csr,val){return Ok(illegal)}}result=Some(old)}},
 _=>return Ok(illegal)}
 if target%(if self.ext(b'C'){2}else{4})!=0{return Ok(Flow::Trap(0,target))}if let Some(v)=result{self.set_reg(rd,v)}self.pc=target;Ok(Flow::Next)
 }
 fn decompress(&self,h:u16)->Option<u32>{
 let c=h as u32;let q=c&3;let f=c>>13;let rd=(c>>7)&31;let rs2=(c>>2)&31;let rp=8+((c>>7)&7);let sp=8+((c>>2)&7);let imm=sext((((c>>12)&1)<<5|((c>>2)&31))as u64,6)as u32;
 let i=|op:u32,d:u32,fun:u32,s:u32,v:u32|((v&4095)<<20)|(s<<15)|(fun<<12)|(d<<7)|op;
 let r=|d:u32,fun:u32,s:u32,t:u32,top:u32|(top<<25)|(t<<20)|(s<<15)|(fun<<12)|(d<<7)|0x33;
 let store=|fun:u32,s:u32,t:u32,v:u32|((v>>5)<<25)|(t<<20)|(s<<15)|(fun<<12)|((v&31)<<7)|0x23;
 let jump=|d:u32,v:u32|((v>>20&1)<<31)|((v>>1&1023)<<21)|((v>>11&1)<<20)|((v>>12&255)<<12)|(d<<7)|0x6f;
 let branch=|fun:u32,s:u32,v:u32|((v>>12&1)<<31)|((v>>5&63)<<25)|(s<<15)|(fun<<12)|((v>>1&15)<<8)|((v>>11&1)<<7)|0x63;
 Some(match(q,f){
 (0,0)=>{let v=((c>>7)&15)<<6|((c>>11)&3)<<4|((c>>5)&1)<<3|((c>>6)&1)<<2;if v==0{return None}i(0x13,sp,0,2,v)},
 (0,2)=>i(3,sp,2,rp,((c>>5)&1)<<6|((c>>10)&7)<<3|((c>>6)&1)<<2),
 (0,3)if self.config.xlen==64=>i(3,sp,3,rp,((c>>5)&3)<<6|((c>>10)&7)<<3),
 (0,6)=>store(2,rp,sp,((c>>5)&1)<<6|((c>>10)&7)<<3|((c>>6)&1)<<2),
 (0,7)if self.config.xlen==64=>store(3,rp,sp,((c>>5)&3)<<6|((c>>10)&7)<<3),
 (1,0)=>i(0x13,rd,0,rd,imm),
 (1,1)if self.config.xlen==64=>{if rd==0{return None}i(0x1b,rd,0,rd,imm)},
 (1,1)|(1,5)=>{let v=((c>>12)&1)<<11|((c>>11)&1)<<4|((c>>9)&3)<<8|((c>>8)&1)<<10|((c>>7)&1)<<6|((c>>6)&1)<<7|((c>>3)&7)<<1|((c>>2)&1)<<5;jump(if f==1{1}else{0},sext(v as u64,12)as u32)},
 (1,2)=>i(0x13,rd,0,0,imm),
 (1,3)=>{if rd==2{let v=((c>>12)&1)<<9|((c>>6)&1)<<4|((c>>5)&1)<<6|((c>>3)&3)<<7|((c>>2)&1)<<5;if v==0{return None}i(0x13,2,0,2,sext(v as u64,10)as u32)}else{if rd==0||imm==0{return None}(imm<<12)|(rd<<7)|0x37}},
 (1,4)=>{let sub=(c>>10)&3;match sub{0|1=>{if self.config.xlen==32&&c&0x1000!=0{return None}i(0x13,rp,5,rp,((c>>2)&31)|((c>>12)&1)<<5|if sub==1{0x400}else{0})},2=>i(0x13,rp,7,rp,imm),_=>{let fun=(c>>5)&3;if c&0x1000==0{r(rp,[0,4,6,7][fun as usize],rp,sp,if fun==0{32}else{0})}else{if self.config.xlen!=64||fun>1{return None}r(rp,0,rp,sp,if fun==0{32}else{0})+8}}}},
 (1,6)|(1,7)=>{let v=((c>>12)&1)<<8|((c>>10)&3)<<3|((c>>5)&3)<<6|((c>>3)&3)<<1|((c>>2)&1)<<5;branch(if f==6{0}else{1},rp,sext(v as u64,9)as u32)},
 (2,0)=>{if self.config.xlen==32&&c&0x1000!=0{return None}i(0x13,rd,1,rd,((c>>2)&31)|((c>>12)&1)<<5)},
 (2,2)=>{if rd==0{return None}i(3,rd,2,2,((c>>12)&1)<<5|((c>>4)&7)<<2|((c>>2)&3)<<6)},
 (2,3)if self.config.xlen==64=>{if rd==0{return None}i(3,rd,3,2,((c>>12)&1)<<5|((c>>5)&3)<<3|((c>>2)&7)<<6)},
 (2,4)=>{if c&0x1000==0{if rs2==0{if rd==0{return None}i(0x67,0,0,rd,0)}else{r(rd,0,0,rs2,0)}}else if rs2==0{if rd==0{0x00100073}else{i(0x67,1,0,rd,0)}}else{r(rd,0,rd,rs2,0)}},
 (2,6)=>store(2,2,rs2,((c>>9)&15)<<2|((c>>7)&3)<<6),
 (2,7)if self.config.xlen==64=>store(3,2,rs2,((c>>10)&7)<<3|((c>>7)&7)<<6),_=>return None})
 }
}
