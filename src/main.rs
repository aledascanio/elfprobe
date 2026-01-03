
use clap::Parser;
use std::path::Path;

mod elf64;
mod maps;
mod proc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Process PID
    #[arg(short, long)]
    pid: u32,

    /// Print per-object PLT relocation symbols (noisy)
    #[arg(long, default_value_t = false)]
    symbols: bool,
}

fn main() {
    let args = Args::parse();

    match proc::read_exe_info(args.pid) {
        Ok(info) => {
            if let Some(elf) = info.elf {
                println!(
                    "exe: {} ({} {:?} {} {})",
                    info.path.display(),
                    match elf.class {
                        proc::ElfClass::Elf32 => "ELF32",
                        proc::ElfClass::Elf64 => "ELF64",
                    },
                    elf.endian,
                    elf.type_name(),
                    elf.machine_name()
                );
            } else {
                println!("exe: {} (non-ELF or unreadable)", info.path.display());
            }
        }
        Err(e) => {
            println!("exe: <unavailable> ({})", e);
        }
    }

    let entries = match maps::read_proc_maps(args.pid) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to read /proc/{}/maps: {}", args.pid, e);
            std::process::exit(1);
        }
    };

    let groups = maps::group_mappings(&entries);

    println!("pid {}: {} map entries, {} groups", args.pid, entries.len(), groups.len());
    for g in groups {
        let likely = if g.likely_elf_dso() { " likely-elf" } else { "" };
        let magic = if g.elf_magic_ok() { " elf-magic" } else { "" };
        println!(
            "{} {} entries={} size=0x{:x}{}{}",
            g.kind,
            g.key,
            g.entries.len(),
            g.total_size(),
            likely,
            magic
        );

        if args.symbols && g.kind == maps::PathnameKind::File && g.elf_magic_ok() {
            let map0 = g.entries.iter().find(|e| e.offset == 0);
            let load_bias = map0
                .and_then(|m| {
                    elf64::compute_load_bias_from_mapping(Path::new(&g.key), m.start, m.offset).ok()
                })
                .or_else(|| g.load_bias_candidate());

            let rels = elf64::parse_x86_64_plt_relocations(Path::new(&g.key), load_bias);
            match rels {
                Ok(rels) => {
                    if !rels.is_empty() {
                        println!("  plt-relocs: {}", rels.len());
                        for r in rels {
                            if let Some(addr) = r.got_runtime_addr {
                                println!("    got=0x{:x} type={} {}", addr, r.r_type, r.sym_name);
                            } else {
                                println!("    got=<unknown> type={} {}", r.r_type, r.sym_name);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  plt-relocs: <unavailable> ({})", e);
                }
            }
        }
    }
}
