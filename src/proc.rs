use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ExeInfo {
    pub path: PathBuf,
    pub elf: Option<ElfInfo>,
}

#[derive(Clone, Debug)]
pub struct ElfInfo {
    pub class: ElfClass,
    pub endian: ElfEndian,
    pub e_type: u16,
    pub e_machine: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElfEndian {
    Little,
    Big,
}

pub fn read_proc_exe(pid: u32) -> io::Result<PathBuf> {
    let link = format!("/proc/{pid}/exe");
    fs::read_link(link)
}

pub fn read_exe_info(pid: u32) -> io::Result<ExeInfo> {
    let path = read_proc_exe(pid)?;
    let elf = read_elf_info(&path).ok();
    Ok(ExeInfo { path, elf })
}

pub fn read_elf_info(path: &PathBuf) -> io::Result<ElfInfo> {
    let bytes = fs::read(path)?;
    parse_elf_header(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn parse_elf_header(bytes: &[u8]) -> Result<ElfInfo, String> {
    if bytes.len() < 0x34 {
        return Err("file too small for ELF header".to_string());
    }
    if bytes.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        return Err("missing ELF magic".to_string());
    }

    let class = match bytes[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        v => return Err(format!("unknown EI_CLASS={}", v)),
    };

    let endian = match bytes[5] {
        1 => ElfEndian::Little,
        2 => ElfEndian::Big,
        v => return Err(format!("unknown EI_DATA={}", v)),
    };

    let read_u16 = |off: usize| -> Result<u16, String> {
        let b0 = *bytes
            .get(off)
            .ok_or_else(|| format!("short read at {off}"))?;
        let b1 = *bytes
            .get(off + 1)
            .ok_or_else(|| format!("short read at {}", off + 1))?;
        Ok(match endian {
            ElfEndian::Little => u16::from_le_bytes([b0, b1]),
            ElfEndian::Big => u16::from_be_bytes([b0, b1]),
        })
    };

    // ELF{32,64} share e_type and e_machine offsets:
    // e_type @ 0x10, e_machine @ 0x12
    let e_type = read_u16(0x10)?;
    let e_machine = read_u16(0x12)?;

    Ok(ElfInfo {
        class,
        endian,
        e_type,
        e_machine,
    })
}

impl ElfInfo {
    pub fn type_name(&self) -> &'static str {
        match self.e_type {
            1 => "ET_REL",
            2 => "ET_EXEC",
            3 => "ET_DYN",
            4 => "ET_CORE",
            _ => "ET_OTHER",
        }
    }

    pub fn machine_name(&self) -> &'static str {
        match self.e_machine {
            3 => "x86",
            62 => "x86_64",
            40 => "arm",
            183 => "aarch64",
            243 => "riscv",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_elf64_little_endian_header() {
        let mut bytes = vec![0u8; 0x40];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2; // ELF64
        bytes[5] = 1; // little
        bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        bytes[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // x86_64

        let info = parse_elf_header(&bytes).unwrap();
        assert_eq!(info.class, ElfClass::Elf64);
        assert_eq!(info.endian, ElfEndian::Little);
        assert_eq!(info.e_type, 2);
        assert_eq!(info.e_machine, 62);
        assert_eq!(info.type_name(), "ET_EXEC");
        assert_eq!(info.machine_name(), "x86_64");
    }
}
