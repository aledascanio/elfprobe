use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct ElfSymbolTables {
    pub symtab: Vec<ElfSym>,
    pub dynsym: Vec<ElfSym>,
}

#[derive(Clone, Debug)]
pub struct ElfSym {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub st_type: u8,
}

#[derive(Clone, Debug)]
pub struct PltRelocation {
    pub got_vaddr: u64,
    pub got_runtime_addr: Option<u64>,
    pub r_type: u32,
    pub kind: PltRelocationKind,
}

pub fn read_symbol_tables(path: &Path) -> io::Result<ElfSymbolTables> {
    let bytes = fs::read(path)?;
    let elf = Elf64File::parse(&bytes)?;

    if elf.e_machine != 62 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported e_machine {} (x86_64 expected)", elf.e_machine),
        ));
    }

    elf.read_symbol_tables(&bytes)
}

pub fn read_plt_ranges(path: &Path) -> io::Result<Vec<(u64, u64)>> {
    let bytes = fs::read(path)?;
    let elf = Elf64File::parse(&bytes)?;

    if elf.e_machine != 62 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported e_machine {} (x86_64 expected)", elf.e_machine),
        ));
    }

    if elf.shoff == 0 || elf.shnum == 0 {
        return Ok(Vec::new());
    }

    let shdrs = elf.read_section_headers(&bytes)?;
    let Some(shstrtab) = shdrs.get(elf.shstrndx as usize).cloned() else {
        return Ok(Vec::new());
    };
    let shstr_bytes = slice_section(&bytes, &shstrtab)?;

    let mut out = Vec::new();
    for s in shdrs.iter() {
        let Some(name) = read_cstr(shstr_bytes, s.sh_name as usize) else {
            continue;
        };
        if name == ".plt" || name == ".plt.sec" || name == ".plt.got" {
            if s.sh_addr != 0 && s.sh_size != 0 {
                out.push((s.sh_addr, s.sh_addr.saturating_add(s.sh_size)));
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub enum PltRelocationKind {
    JumpSlot { sym_name: String },
    IRelative { resolver_vaddr: u64, resolver_runtime_addr: Option<u64> },
    Other { sym_name: Option<String> },
}

pub fn compute_load_bias_from_mapping(path: &Path, map_start: u64, map_offset: u64) -> io::Result<u64> {
    let bytes = fs::read(path)?;
    let elf = Elf64File::parse(&bytes)?;

    let Some(seg) = elf
        .phdrs
        .iter()
        .find(|p| p.p_type == PT_LOAD && p.p_offset == map_offset)
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no PT_LOAD segment matching mapping offset",
        ));
    };

    Ok(map_start.wrapping_sub(seg.p_vaddr))
}

pub fn parse_x86_64_plt_relocations(path: &Path, load_bias: Option<u64>) -> io::Result<Vec<PltRelocation>> {
    let bytes = fs::read(path)?;
    let elf = Elf64File::parse(&bytes)?;

    if elf.e_machine != 62 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported e_machine {} (x86_64 expected)", elf.e_machine),
        ));
    }

    let dyn_tags = elf.read_dynamic_tags(&bytes)?;

    let Some(jmprel_vaddr) = dyn_tags.get(&DT_JMPREL).copied() else {
        return Ok(Vec::new());
    };
    let Some(pltrelsz) = dyn_tags.get(&DT_PLTRELSZ).copied() else {
        return Ok(Vec::new());
    };

    let pltrel = dyn_tags.get(&DT_PLTREL).copied().unwrap_or(0);
    if pltrel != DT_RELA as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported DT_PLTREL {} (DT_RELA expected)", pltrel),
        ));
    }

    let symtab_vaddr = *dyn_tags
        .get(&DT_SYMTAB)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing DT_SYMTAB"))?;
    let strtab_vaddr = *dyn_tags
        .get(&DT_STRTAB)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing DT_STRTAB"))?;

    let syment = dyn_tags.get(&DT_SYMENT).copied().unwrap_or(24);
    if syment != 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported DT_SYMENT {} (24 expected)", syment),
        ));
    }

    let jmprel_off = elf
        .vaddr_to_offset(jmprel_vaddr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DT_JMPREL not in PT_LOAD"))?;
    let symtab_off = elf
        .vaddr_to_offset(symtab_vaddr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DT_SYMTAB not in PT_LOAD"))?;
    let strtab_off = elf
        .vaddr_to_offset(strtab_vaddr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DT_STRTAB not in PT_LOAD"))?;

    let strtab = &bytes[strtab_off as usize..];

    let rela_count = (pltrelsz / 24) as usize;
    let mut out = Vec::with_capacity(rela_count);

    for i in 0..rela_count {
        let off = jmprel_off as usize + i * 24;
        let rela = read_rela(&bytes, off)?;

        let r_type = (rela.r_info & 0xffff_ffff) as u32;
        let sym_index = (rela.r_info >> 32) as u32;

        let got_runtime_addr = load_bias.map(|b| b.wrapping_add(rela.r_offset));

        // x86_64 relocation types of interest:
        // - R_X86_64_JUMP_SLOT (7): normal PLT/GOT binding
        // - R_X86_64_IRELATIVE (37): IFUNC-style resolver; no symbol name
        let kind = match r_type {
            7 => {
                let sym = read_sym(&bytes, symtab_off as usize + (sym_index as usize) * 24)?;
                let sym_name = read_cstr(strtab, sym.st_name as usize)
                    .unwrap_or_else(|| format!("<bad-strtab:{}>", sym.st_name));
                PltRelocationKind::JumpSlot { sym_name }
            }
            37 => {
                let resolver_vaddr = rela._r_addend as u64;
                let resolver_runtime_addr = load_bias.map(|b| b.wrapping_add(resolver_vaddr));
                PltRelocationKind::IRelative {
                    resolver_vaddr,
                    resolver_runtime_addr,
                }
            }
            _ => {
                let sym_name = if sym_index == 0 {
                    None
                } else {
                    let sym = read_sym(&bytes, symtab_off as usize + (sym_index as usize) * 24)?;
                    Some(
                        read_cstr(strtab, sym.st_name as usize)
                            .unwrap_or_else(|| format!("<bad-strtab:{}>", sym.st_name)),
                    )
                };
                PltRelocationKind::Other { sym_name }
            }
        };

        out.push(PltRelocation {
            got_vaddr: rela.r_offset,
            got_runtime_addr,
            r_type,
            kind,
        });
    }

    Ok(out)
}

// --- ELF64 parsing (minimal, x86_64-focused) ---

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

pub const DT_NULL: i64 = 0;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_SYMENT: i64 = 11;
pub const DT_JMPREL: i64 = 23;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTREL: i64 = 20;

#[derive(Clone, Debug)]
struct Elf64File {
    e_machine: u16,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    phdrs: Vec<Elf64Phdr>,

    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[derive(Clone, Debug)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

#[derive(Clone, Debug)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[derive(Clone, Debug)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    _r_addend: i64,
}

#[derive(Clone, Debug)]
struct Elf64Sym {
    st_name: u32,
    _st_info: u8,
    _st_other: u8,
    _st_shndx: u16,
    _st_value: u64,
    _st_size: u64,
}

impl Elf64File {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 0x40 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
        }
        if bytes.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "missing ELF magic"));
        }
        if bytes[EI_CLASS] != ELFCLASS64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not ELF64"));
        }
        if bytes[EI_DATA] != ELFDATA2LSB {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "only little-endian supported",
            ));
        }

        let e_machine = read_u16(bytes, 0x12)?;
        let phoff = read_u64(bytes, 0x20)?;
        let phentsize = read_u16(bytes, 0x36)?;
        let phnum = read_u16(bytes, 0x38)?;

        let shoff = read_u64(bytes, 0x28)?;
        let shentsize = read_u16(bytes, 0x3a)?;
        let shnum = read_u16(bytes, 0x3c)?;
        let shstrndx = read_u16(bytes, 0x3e)?;

        if phentsize as usize != 56 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected e_phentsize {}", phentsize),
            ));
        }

        let mut phdrs = Vec::with_capacity(phnum as usize);
        for i in 0..phnum as usize {
            let off = phoff as usize + i * 56;
            phdrs.push(read_phdr(bytes, off)?);
        }

        Ok(Self {
            e_machine,
            phoff,
            phentsize,
            phnum,
            phdrs,
            shoff,
            shentsize,
            shnum,
            shstrndx,
        })
    }

    fn vaddr_to_offset(&self, vaddr: u64) -> Option<u64> {
        for p in &self.phdrs {
            if p.p_type != PT_LOAD {
                continue;
            }
            if vaddr >= p.p_vaddr && vaddr < p.p_vaddr.saturating_add(p.p_memsz) {
                return Some(p.p_offset + (vaddr - p.p_vaddr));
            }
        }
        None
    }

    fn read_dynamic_tags(&self, bytes: &[u8]) -> io::Result<HashMap<i64, u64>> {
        let dyn_ph = self
            .phdrs
            .iter()
            .find(|p| p.p_type == PT_DYNAMIC)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PT_DYNAMIC"))?;

        let dyn_off = dyn_ph.p_offset as usize;
        let dyn_sz = dyn_ph.p_filesz as usize;
        if dyn_off + dyn_sz > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "PT_DYNAMIC out of range"));
        }

        let mut tags = HashMap::new();
        let count = dyn_sz / 16;
        for i in 0..count {
            let off = dyn_off + i * 16;
            let d = read_dyn(bytes, off)?;
            if d.d_tag == DT_NULL {
                break;
            }
            // Keep first occurrence for now.
            tags.entry(d.d_tag).or_insert(d.d_val);
        }

        Ok(tags)
    }

    fn read_symbol_tables(&self, bytes: &[u8]) -> io::Result<ElfSymbolTables> {
        let (symtab, strtab) = self.find_section_pair(bytes, ".symtab", ".strtab")?;
        let (dynsym, dynstr) = self.find_section_pair(bytes, ".dynsym", ".dynstr")?;

        let symtab_syms = if let (Some(sym), Some(strs)) = (symtab, strtab) {
            parse_symtab(bytes, &sym, &strs)?
        } else {
            Vec::new()
        };

        let dynsym_syms = if let (Some(sym), Some(strs)) = (dynsym, dynstr) {
            parse_symtab(bytes, &sym, &strs)?
        } else {
            Vec::new()
        };

        Ok(ElfSymbolTables {
            symtab: symtab_syms,
            dynsym: dynsym_syms,
        })
    }

    fn find_section_pair(
        &self,
        bytes: &[u8],
        sym_name: &str,
        str_name: &str,
    ) -> io::Result<(Option<Elf64Shdr>, Option<Elf64Shdr>)> {
        if self.shoff == 0 || self.shnum == 0 {
            return Ok((None, None));
        }
        if self.shentsize as usize != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected e_shentsize {}", self.shentsize),
            ));
        }

        let shstr = self.read_section_headers(bytes)?;
        let Some(shstrtab) = shstr.get(self.shstrndx as usize).cloned() else {
            return Ok((None, None));
        };
        let shstr_bytes = slice_section(bytes, &shstrtab)?;

        let mut sym: Option<Elf64Shdr> = None;
        let mut strs: Option<Elf64Shdr> = None;

        for s in shstr.iter() {
            let name = read_cstr(shstr_bytes, s.sh_name as usize);
            let Some(name) = name else {
                continue;
            };
            if name == sym_name {
                sym = Some(s.clone());
            } else if name == str_name {
                strs = Some(s.clone());
            }
        }

        Ok((sym, strs))
    }

    fn read_section_headers(&self, bytes: &[u8]) -> io::Result<Vec<Elf64Shdr>> {
        let off = self.shoff as usize;
        let total = (self.shnum as usize)
            .checked_mul(self.shentsize as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "section header overflow"))?;
        if off + total > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "section headers out of range",
            ));
        }

        let mut out = Vec::with_capacity(self.shnum as usize);
        for i in 0..self.shnum as usize {
            let shoff = off + i * 64;
            out.push(read_shdr(bytes, shoff)?);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

fn read_phdr(bytes: &[u8], off: usize) -> io::Result<Elf64Phdr> {
    Ok(Elf64Phdr {
        p_type: read_u32_at(bytes, off + 0)?,
        p_flags: read_u32_at(bytes, off + 4)?,
        p_offset: read_u64_at(bytes, off + 8)?,
        p_vaddr: read_u64_at(bytes, off + 16)?,
        p_filesz: read_u64_at(bytes, off + 32)?,
        p_memsz: read_u64_at(bytes, off + 40)?,
    })
}

fn read_shdr(bytes: &[u8], off: usize) -> io::Result<Elf64Shdr> {
    Ok(Elf64Shdr {
        sh_name: read_u32_at(bytes, off + 0)?,
        sh_type: read_u32_at(bytes, off + 4)?,
        sh_flags: read_u64_at(bytes, off + 8)?,
        sh_addr: read_u64_at(bytes, off + 16)?,
        sh_offset: read_u64_at(bytes, off + 24)?,
        sh_size: read_u64_at(bytes, off + 32)?,
        sh_link: read_u32_at(bytes, off + 40)?,
        sh_info: read_u32_at(bytes, off + 44)?,
        sh_addralign: read_u64_at(bytes, off + 48)?,
        sh_entsize: read_u64_at(bytes, off + 56)?,
    })
}

fn slice_section<'a>(bytes: &'a [u8], sh: &Elf64Shdr) -> io::Result<&'a [u8]> {
    let off = sh.sh_offset as usize;
    let sz = sh.sh_size as usize;
    if off + sz > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "section out of range"));
    }
    Ok(&bytes[off..off + sz])
}

fn parse_symtab(bytes: &[u8], sym: &Elf64Shdr, strs: &Elf64Shdr) -> io::Result<Vec<ElfSym>> {
    if sym.sh_entsize != 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected symbol entsize {}", sym.sh_entsize),
        ));
    }
    let sym_bytes = slice_section(bytes, sym)?;
    let str_bytes = slice_section(bytes, strs)?;

    let count = sym_bytes.len() / 24;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 24;
        let st_name = u32::from_le_bytes([
            sym_bytes[off],
            sym_bytes[off + 1],
            sym_bytes[off + 2],
            sym_bytes[off + 3],
        ]);
        let st_info = sym_bytes[off + 4];
        let st_type = st_info & 0x0f;
        let st_value = u64::from_le_bytes([
            sym_bytes[off + 8],
            sym_bytes[off + 9],
            sym_bytes[off + 10],
            sym_bytes[off + 11],
            sym_bytes[off + 12],
            sym_bytes[off + 13],
            sym_bytes[off + 14],
            sym_bytes[off + 15],
        ]);
        let st_size = u64::from_le_bytes([
            sym_bytes[off + 16],
            sym_bytes[off + 17],
            sym_bytes[off + 18],
            sym_bytes[off + 19],
            sym_bytes[off + 20],
            sym_bytes[off + 21],
            sym_bytes[off + 22],
            sym_bytes[off + 23],
        ]);

        let name = read_cstr(str_bytes, st_name as usize).unwrap_or_else(|| "<noname>".to_string());
        out.push(ElfSym {
            name,
            value: st_value,
            size: st_size,
            st_type,
        });
    }
    Ok(out)
}

fn read_dyn(bytes: &[u8], off: usize) -> io::Result<Elf64Dyn> {
    Ok(Elf64Dyn {
        d_tag: read_i64_at(bytes, off + 0)?,
        d_val: read_u64_at(bytes, off + 8)?,
    })
}

fn read_rela(bytes: &[u8], off: usize) -> io::Result<Elf64Rela> {
    if off + 24 > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short RELA"));
    }
    Ok(Elf64Rela {
        r_offset: read_u64_at(bytes, off + 0)?,
        r_info: read_u64_at(bytes, off + 8)?,
        _r_addend: read_i64_at(bytes, off + 16)?,
    })
}

fn read_sym(bytes: &[u8], off: usize) -> io::Result<Elf64Sym> {
    if off + 24 > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short SYM"));
    }
    Ok(Elf64Sym {
        st_name: read_u32_at(bytes, off + 0)?,
        _st_info: *bytes.get(off + 4).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short SYM"))?,
        _st_other: *bytes.get(off + 5).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short SYM"))?,
        _st_shndx: read_u16_at(bytes, off + 6)?,
        _st_value: read_u64_at(bytes, off + 8)?,
        _st_size: read_u64_at(bytes, off + 16)?,
    })
}

fn read_cstr(bytes: &[u8], off: usize) -> Option<String> {
    if off >= bytes.len() {
        return None;
    }
    let end = bytes[off..].iter().position(|&b| b == 0).map(|p| off + p)?;
    std::str::from_utf8(&bytes[off..end]).ok().map(|s| s.to_string())
}

fn read_u16(bytes: &[u8], off: usize) -> io::Result<u16> {
    read_u16_at(bytes, off)
}

fn read_u64(bytes: &[u8], off: usize) -> io::Result<u64> {
    read_u64_at(bytes, off)
}

fn read_u16_at(bytes: &[u8], off: usize) -> io::Result<u16> {
    if off + 2 > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
    }
    Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u32_at(bytes: &[u8], off: usize) -> io::Result<u32> {
    if off + 4 > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

fn read_u64_at(bytes: &[u8], off: usize) -> io::Result<u64> {
    if off + 8 > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
    }
    Ok(u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ]))
}

fn read_i64_at(bytes: &[u8], off: usize) -> io::Result<i64> {
    Ok(read_u64_at(bytes, off)? as i64)
}
