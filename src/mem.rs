use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

pub struct MemReader {
    file: File,
}

impl MemReader {
    pub fn open(pid: u32) -> io::Result<Self> {
        let path = format!("/proc/{pid}/mem");
        let file = File::open(path)?;
        Ok(Self { file })
    }

    pub fn read_exact(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(buf, addr)?;
        Ok(())
    }

    pub fn read_u64(&self, addr: u64) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn read_u32(&self, addr: u64) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn read_i64(&self, addr: u64) -> io::Result<i64> {
        Ok(self.read_u64(addr)? as i64)
    }

    pub fn read_cstring(&self, addr: u64, max_len: usize) -> io::Result<String> {
        if addr == 0 {
            return Ok(String::new());
        }

        const CHUNK: usize = 256;
        let mut out = Vec::with_capacity(64);
        let mut buf = [0u8; CHUNK];
        let mut read = 0usize;

        while read < max_len {
            let want = CHUNK.min(max_len - read);
            let chunk = &mut buf[..want];
            // A C string may sit near the end of a readable region, so a short
            // read here is expected; fall back to a byte-wise read for the tail.
            match self.read_exact(addr + read as u64, chunk) {
                Ok(()) => {}
                Err(_) => return self.read_cstring_byte_wise(addr + read as u64, &mut out, max_len - read),
            }
            if let Some(nul) = chunk.iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..nul]);
                return Ok(String::from_utf8_lossy(&out).to_string());
            }
            out.extend_from_slice(chunk);
            read += want;
        }

        Ok(String::from_utf8_lossy(&out).to_string())
    }

    fn read_cstring_byte_wise(
        &self,
        addr: u64,
        out: &mut Vec<u8>,
        max_len: usize,
    ) -> io::Result<String> {
        for i in 0..max_len {
            let mut b = [0u8; 1];
            if self.read_exact(addr + i as u64, &mut b).is_err() {
                break;
            }
            if b[0] == 0 {
                break;
            }
            out.push(b[0]);
        }
        Ok(String::from_utf8_lossy(out).to_string())
    }
}
