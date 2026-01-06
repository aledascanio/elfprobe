use std::fs;
use std::io;

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;

#[derive(Clone, Debug)]
pub struct AuxvInfo {
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
}

pub fn read_auxv(pid: u32) -> io::Result<AuxvInfo> {
    let path = format!("/proc/{pid}/auxv");
    let bytes = fs::read(path)?;

    if bytes.len() % 16 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected /proc/<pid>/auxv size",
        ));
    }

    let mut phdr = None;
    let mut phent = None;
    let mut phnum = None;

    for chunk in bytes.chunks_exact(16) {
        let key = u64::from_ne_bytes(chunk[0..8].try_into().unwrap());
        let val = u64::from_ne_bytes(chunk[8..16].try_into().unwrap());
        if key == AT_NULL {
            break;
        }
        match key {
            AT_PHDR => phdr = Some(val),
            AT_PHENT => phent = Some(val),
            AT_PHNUM => phnum = Some(val),
            _ => {}
        }
    }

    Ok(AuxvInfo {
        phdr: phdr.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing AT_PHDR"))?,
        phent: phent
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing AT_PHENT"))?,
        phnum: phnum
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing AT_PHNUM"))?,
    })
}
