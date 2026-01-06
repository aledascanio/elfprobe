use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::elf64;
use crate::elf64::{ElfSym, ElfSymbolTables};
use crate::maps::MapEntry;

pub struct Symbolizer {
    maps: Vec<MapEntry>,
    cache: HashMap<PathBuf, io::Result<ElfSymbolTables>>,
}

impl Symbolizer {
    pub fn new(maps: Vec<MapEntry>) -> Self {
        Self {
            maps,
            cache: HashMap::new(),
        }
    }

    pub fn symbolize_runtime_addr(&mut self, runtime_addr: u64) -> Option<String> {
        let map = self
            .maps
            .iter()
            .find(|m| runtime_addr >= m.start && runtime_addr < m.end)?;

        let path_str = map.pathname.as_deref()?;
        if path_str.starts_with('[') {
            return None;
        }
        let path_str = path_str.trim_end_matches(" (deleted)");
        let path = PathBuf::from(path_str);

        let load_bias =
            elf64::compute_load_bias_from_mapping(Path::new(&path), map.start, map.offset).ok()?;
        let vaddr = runtime_addr.wrapping_sub(load_bias);

        let tables = self
            .cache
            .entry(path.clone())
            .or_insert_with(|| elf64::read_symbol_tables(&path));

        let Ok(tables) = tables else {
            return None;
        };

        tables.lookup(vaddr).map(|(name, sym_addr)| {
            let delta = vaddr.saturating_sub(sym_addr);
            if delta == 0 {
                format!("{}", name)
            } else {
                format!("{}+0x{:x}", name, delta)
            }
        })
    }
}

impl ElfSymbolTables {
    pub fn lookup(&self, vaddr: u64) -> Option<(String, u64)> {
        // Prefer symtab, then dynsym
        lookup_in(&self.symtab, vaddr).or_else(|| lookup_in(&self.dynsym, vaddr))
    }
}

fn lookup_in(syms: &[ElfSym], vaddr: u64) -> Option<(String, u64)> {
    // First try: range match using size if available.
    let mut best_range: Option<&ElfSym> = None;
    for s in syms {
        if s.value == 0 {
            continue;
        }
        if s.size != 0 && vaddr >= s.value && vaddr < s.value.saturating_add(s.size) {
            best_range = Some(s);
            break;
        }
    }
    if let Some(s) = best_range {
        return Some((s.name.clone(), s.value));
    }

    // Fallback: nearest preceding symbol.
    let mut best: Option<&ElfSym> = None;
    for s in syms {
        if s.value == 0 {
            continue;
        }
        if vaddr >= s.value {
            match best {
                None => best = Some(s),
                Some(b) if s.value > b.value => best = Some(s),
                _ => {}
            }
        }
    }

    best.map(|s| (s.name.clone(), s.value))
}
