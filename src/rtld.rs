use std::io;

use crate::auxv;
use crate::mem::MemReader;

const PT_DYNAMIC: u32 = 2;
const PT_PHDR: u32 = 6;

const DT_NULL: i64 = 0;
const DT_DEBUG: i64 = 21;

#[derive(Clone, Debug)]
pub struct LinkMapEntry {
    pub l_addr: u64,
    pub l_ld: u64,
    pub l_name: String,
}

pub fn read_link_map(pid: u32) -> io::Result<Vec<LinkMapEntry>> {
    let aux = auxv::read_auxv(pid)?;
    let mem = MemReader::open(pid)?;

    if aux.phent != 56 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported AT_PHENT {} (ELF64 expected)", aux.phent),
        ));
    }

    let phdrs = read_phdrs(&mem, aux.phdr, aux.phnum as usize)?;
    let base = compute_base(aux.phdr, &phdrs)?;

    let dyn_ph = phdrs
        .iter()
        .find(|p| p.p_type == PT_DYNAMIC)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PT_DYNAMIC"))?;

    let dyn_addr = base.wrapping_add(dyn_ph.p_vaddr);
    let r_debug_addr = read_dt_debug(&mem, dyn_addr, dyn_ph.p_memsz)?;

    let r_map = read_r_map_ptr(&mem, r_debug_addr)?;
    traverse_link_map(&mem, r_map)
}

fn read_phdrs(mem: &MemReader, phdr_addr: u64, phnum: usize) -> io::Result<Vec<Elf64Phdr>> {
    let mut out = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let off = phdr_addr + (i as u64) * 56;
        out.push(read_phdr(mem, off)?);
    }
    Ok(out)
}

fn compute_base(phdr_addr: u64, phdrs: &[Elf64Phdr]) -> io::Result<u64> {
    let Some(phdr_seg) = phdrs.iter().find(|p| p.p_type == PT_PHDR) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing PT_PHDR; cannot compute load bias",
        ));
    };

    Ok(phdr_addr.wrapping_sub(phdr_seg.p_vaddr))
}

fn read_dt_debug(mem: &MemReader, dyn_addr: u64, dyn_memsz: u64) -> io::Result<u64> {
    let count = (dyn_memsz / 16).min(4096) as usize;
    for i in 0..count {
        let off = dyn_addr + (i as u64) * 16;
        let tag = mem.read_i64(off)?;
        let val = mem.read_u64(off + 8)?;
        if tag == DT_NULL {
            break;
        }
        if tag == DT_DEBUG {
            return Ok(val);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "DT_DEBUG not found in PT_DYNAMIC",
    ))
}

fn read_r_map_ptr(mem: &MemReader, r_debug_addr: u64) -> io::Result<u64> {
    // struct r_debug (glibc, 64-bit):
    // int r_version; (4)
    // padding (4)
    // struct link_map *r_map; (8) @ +8
    // ...
    mem.read_u64(r_debug_addr + 8)
}

fn traverse_link_map(mem: &MemReader, mut cur: u64) -> io::Result<Vec<LinkMapEntry>> {
    let mut out = Vec::new();
    let mut steps = 0usize;

    while cur != 0 {
        if steps > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "link_map traversal seems infinite",
            ));
        }
        steps += 1;

        let l_addr = mem.read_u64(cur + 0)?;
        let l_name_ptr = mem.read_u64(cur + 8)?;
        let l_ld = mem.read_u64(cur + 16)?;
        let l_next = mem.read_u64(cur + 24)?;

        let l_name = mem.read_cstring(l_name_ptr, 4096).unwrap_or_default();

        out.push(LinkMapEntry { l_addr, l_ld, l_name });
        cur = l_next;
    }

    Ok(out)
}

#[derive(Clone, Debug)]
struct Elf64Phdr {
    p_type: u32,
    _p_flags: u32,
    _p_offset: u64,
    p_vaddr: u64,
    _p_paddr: u64,
    _p_filesz: u64,
    p_memsz: u64,
    _p_align: u64,
}

fn read_phdr(mem: &MemReader, addr: u64) -> io::Result<Elf64Phdr> {
    Ok(Elf64Phdr {
        p_type: mem.read_u32(addr + 0)?,
        _p_flags: mem.read_u32(addr + 4)?,
        _p_offset: mem.read_u64(addr + 8)?,
        p_vaddr: mem.read_u64(addr + 16)?,
        _p_paddr: mem.read_u64(addr + 24)?,
        _p_filesz: mem.read_u64(addr + 32)?,
        p_memsz: mem.read_u64(addr + 40)?,
        _p_align: mem.read_u64(addr + 48)?,
    })
}
