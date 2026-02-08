use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::colors;
use crate::elf64;
use crate::maps;
use crate::mem::MemReader;
use crate::rtld;
use crate::symbolize::Symbolizer;

#[derive(Clone, Debug)]
struct WatchedSlot {
    obj: String,
    sym: String,
    got: u64,
    last: u64,
}

pub fn watch_bindings(
    pid: u32,
    maps: Vec<crate::maps::MapEntry>,
    interval_ms: u64,
    iterations: Option<u64>,
    filter: Option<String>,
    show_non_elf: bool,
    colors: bool,
) -> io::Result<()> {
    let mem = MemReader::open(pid)?;
    let mut symbolizer = Symbolizer::new(maps);
    let theme = colors::Theme::new(colors);

    let link_map = rtld::read_link_map(pid)?;

    let mut slots = Vec::new();

    for e in link_map {
        let path = if e.l_name.is_empty() {
            None
        } else {
            Some(e.l_name)
        };
        let Some(path) = path else {
            continue;
        };

        if let Some(ref needle) = filter {
            if !path.contains(needle) {
                continue;
            }
        }
        if !show_non_elf {
            if !path.starts_with('/') {
                continue;
            }
            let is_elf = maps::is_elf_magic_file(std::path::Path::new(&path)).unwrap_or(false);
            if !is_elf {
                continue;
            }
        }

        let rels = match elf64::parse_x86_64_plt_relocations(Path::new(&path), Some(e.l_addr)) {
            Ok(v) => v,
            Err(_) => continue,
        };

        for r in rels {
            let elf64::PltRelocationKind::JumpSlot { sym_name } = r.kind else {
                continue;
            };
            let Some(got) = r.got_runtime_addr else {
                continue;
            };
            let last = mem.read_u64(got).unwrap_or(0);
            slots.push(WatchedSlot {
                obj: path.clone(),
                sym: sym_name,
                got,
                last,
            });
        }
    }

    println!(
        "watching {} GOT slots (interval {}ms)",
        slots.len(),
        interval_ms
    );

    let mut it = 0u64;
    loop {
        if let Some(max) = iterations {
            if it >= max {
                break;
            }
        }
        it += 1;

        let mut changed = Vec::new();

        for (idx, s) in slots.iter_mut().enumerate() {
            let cur = match mem.read_u64(s.got) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if cur != s.last {
                changed.push((idx, s.last, cur));
                s.last = cur;
            }
        }

        if !changed.is_empty() {
            // group by object for nicer output
            let mut by_obj: HashMap<&str, Vec<(usize, u64, u64)>> = HashMap::new();
            for (idx, old, new) in changed {
                by_obj
                    .entry(slots[idx].obj.as_str())
                    .or_default()
                    .push((idx, old, new));
            }

            for (obj, items) in by_obj {
                let obj_str = if obj.starts_with('/') {
                    theme.path(obj)
                } else {
                    obj.to_string()
                };
                println!("obj {}:", obj_str);
                for (idx, old, new) in items {
                    let sym = &slots[idx].sym;
                    let new_name = symbolizer.symbolize_runtime_addr(new);
                    if let Some(nn) = new_name {
                        println!(
                            "  {} got={} {} -> {} ({})",
                            theme.symbol(sym),
                            theme.address(slots[idx].got),
                            theme.address(old),
                            theme.address(new),
                            theme.symbol(&nn)
                        );
                    } else {
                        println!(
                            "  {} got={} {} -> {}",
                            theme.symbol(sym),
                            theme.address(slots[idx].got),
                            theme.address(old),
                            theme.address(new)
                        );
                    }
                }
            }
        }

        thread::sleep(Duration::from_millis(interval_ms));
    }

    Ok(())
}
