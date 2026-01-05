use std::io;
use std::path::Path;

use crate::elf64;
use crate::mem::MemReader;
use crate::rtld;

#[derive(Clone, Debug)]
pub struct BindingSummary {
    pub name: String,
    pub base: u64,
    pub jump_slots: usize,
    pub unresolved: usize,
    pub resolved: usize,
    pub unknown: usize,
}

pub fn summarize_bindings(pid: u32) -> io::Result<Vec<BindingSummary>> {
    let link_map = rtld::read_link_map(pid)?;
    let mem = MemReader::open(pid)?;

    let mut out = Vec::new();

    for e in link_map {
        let path = if e.l_name.is_empty() { None } else { Some(e.l_name.clone()) };
        let Some(path) = path else {
            // Main executable sometimes has empty l_name; skip for now.
            continue;
        };

        let plt_ranges = elf64::read_plt_ranges(Path::new(&path)).unwrap_or_default();
        let plt_runtime_ranges: Vec<(u64, u64)> = plt_ranges
            .into_iter()
            .map(|(a, b)| (e.l_addr.wrapping_add(a), e.l_addr.wrapping_add(b)))
            .collect();

        let rels = match elf64::parse_x86_64_plt_relocations(Path::new(&path), Some(e.l_addr)) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let mut jump_slots = 0usize;
        let mut unresolved = 0usize;
        let mut resolved = 0usize;
        let mut unknown = 0usize;

        for r in rels {
            let elf64::PltRelocationKind::JumpSlot { .. } = r.kind else {
                continue;
            };
            jump_slots += 1;

            let Some(got_addr) = r.got_runtime_addr else {
                unknown += 1;
                continue;
            };

            let val = match mem.read_u64(got_addr) {
                Ok(v) => v,
                Err(_) => {
                    unknown += 1;
                    continue;
                }
            };

            if points_into_ranges(val, &plt_runtime_ranges) {
                unresolved += 1;
            } else {
                resolved += 1;
            }
        }

        out.push(BindingSummary {
            name: path,
            base: e.l_addr,
            jump_slots,
            unresolved,
            resolved,
            unknown,
        });
    }

    Ok(out)
}

fn points_into_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|(a, b)| addr >= *a && addr < *b)
}
