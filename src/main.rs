use clap::Parser;
use std::path::Path;

mod colors;
mod elf64;
mod auxv;
mod binding;
mod mem;
mod maps;
mod proc;
mod rtld;
mod symbolize;
mod watch;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Process PID
    #[arg(short, long)]
    pid: u32,

    /// Enable ANSI colors in output
    #[arg(long, default_value_t = false)]
    colors: bool,

    /// Print per-object PLT relocation symbols (noisy)
    #[arg(long, default_value_t = false)]
    symbols: bool,

    /// Print rtld link_map
    #[arg(long, default_value_t = false)]
    rtld: bool,

    /// Print binding summary
    #[arg(long, default_value_t = false)]
    binding: bool,

    /// ELF-only filtering
    #[arg(long, default_value_t = false)]
    elf_only: bool,

    /// Filter by pathname
    #[arg(long)]
    filter: Option<String>,

    /// Max symbols to print
    #[arg(long)]
    max_symbols: Option<usize>,

    /// Watch GOT slot changes to observe first-time PLT bindings (requires /proc/<pid>/mem)
    #[arg(long, default_value_t = false)]
    watch_bindings: bool,

    #[arg(long, default_value_t = 500)]
    interval_ms: u64,

    /// Number of polling iterations (omit to run forever)
    #[arg(long)]
    iterations: Option<u64>,
}

fn main() {
    let args = Args::parse();

    let theme = colors::Theme::new(args.colors);

    match proc::read_exe_info(args.pid) {
        Ok(info) => {
            if let Some(elf) = info.elf {
                println!(
                    "exe: {} ({} {:?} {} {})",
                    theme.path(&info.path.display().to_string()),
                    match elf.class {
                        proc::ElfClass::Elf32 => "ELF32",
                        proc::ElfClass::Elf64 => "ELF64",
                    },
                    elf.endian,
                    elf.type_name(),
                    elf.machine_name()
                );
            } else {
                println!(
                    "exe: {} (non-ELF or unreadable)",
                    theme.path(&info.path.display().to_string())
                );
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

    if args.watch_bindings {
        if let Err(e) = watch::watch_bindings(
            args.pid,
            entries.clone(),
            args.interval_ms,
            args.iterations,
            args.filter.clone(),
            args.elf_only,
            args.colors,
        ) {
            eprintln!("failed to watch bindings: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let mut symbolizer = if args.symbols {
        Some(symbolize::Symbolizer::new(entries.clone()))
    } else {
        None
    };

    let groups = maps::group_mappings(&entries);

    println!("pid {}: {} map entries, {} groups", args.pid, entries.len(), groups.len());
    for g in groups {
        if args.elf_only {
            if !(g.kind == maps::PathnameKind::File && g.elf_magic_ok()) {
                continue;
            }
        }
        if let Some(ref needle) = args.filter {
            if !g.key.contains(needle) {
                continue;
            }
        }

        let likely = if g.likely_elf_dso() { " likely-elf" } else { "" };
        let magic = if g.elf_magic_ok() { " elf-magic" } else { "" };

        let key = if g.kind == maps::PathnameKind::File {
            theme.path(&g.key)
        } else {
            g.key.clone()
        };
        println!(
            "{} {} entries={} size=0x{:x}{}{}",
            g.kind,
            key,
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
                        let total = rels.len();
                        println!("  plt-relocs: {}", total);
                        let max = args.max_symbols.unwrap_or(total);
                        let mut printed = 0usize;

                        for r in rels.into_iter().take(max) {

                            let got_str = if let Some(addr) = r.got_runtime_addr {
                                theme.address(addr)
                            } else {
                                "<unknown>".to_string()
                            };

                            match r.kind {
                                elf64::PltRelocationKind::JumpSlot { sym_name } => {
                                    println!(
                                        "    got={} JUMP_SLOT {}",
                                        got_str,
                                        theme.symbol(&sym_name)
                                    );
                                }
                                elf64::PltRelocationKind::IRelative { resolver_runtime_addr } => {
                                    if let Some(res) = resolver_runtime_addr {
                                        let name = symbolizer
                                            .as_mut()
                                            .and_then(|s| s.symbolize_runtime_addr(res));
                                        if let Some(name) = name {
                                            println!(
                                                "    got={} IRELATIVE resolver={} name={}",
                                                got_str,
                                                theme.address(res),
                                                theme.symbol(&name)
                                            );
                                        } else {
                                            println!(
                                                "    got={} IRELATIVE resolver={}",
                                                got_str,
                                                theme.address(res)
                                            );
                                        }
                                    } else {
                                        println!("    got={} IRELATIVE resolver=<unknown>", got_str);
                                    }
                                }
                                elf64::PltRelocationKind::Other { sym_name } => {
                                    if let Some(sym) = sym_name {
                                        println!(
                                            "    got={} type={} {}",
                                            got_str,
                                            r.r_type,
                                            theme.symbol(&sym)
                                        );
                                    } else {
                                        println!("    got={} type={}", got_str, r.r_type);
                                    }
                                }
                            }

                            printed += 1;
                        }

                        if total > printed {
                            println!("    ... {} more", total - printed);
                        }
                    }
                }
                Err(e) => {
                    println!("  plt-relocs: <unavailable> ({})", e);
                }
            }
        }
    }

    if args.rtld {
        match rtld::read_link_map(args.pid) {
            Ok(entries) => {
                println!("rtld link_map:");
                for (i, e) in entries.iter().enumerate() {
                    let name = if e.l_name.is_empty() { "<main>" } else { &e.l_name };
                    if let Some(ref needle) = args.filter {
                        if !name.contains(needle) {
                            continue;
                        }
                    }
                    if args.elf_only {
                        if let Some(p) = name.strip_prefix("/") {
                            let _ = p;
                        }
                        // Best-effort: only filter if we have a real path.
                        if !name.starts_with('/') {
                            continue;
                        }
                        let is_elf = std::fs::read(name)
                            .ok()
                            .map(|b| b.len() >= 4 && b[0..4] == [0x7f, b'E', b'L', b'F'])
                            .unwrap_or(false);
                        if !is_elf {
                            continue;
                        }
                    }
                    let name_str = if name.starts_with('/') {
                        theme.path(name)
                    } else {
                        name.to_string()
                    };
                    println!(
                        "  [{}] base={} l_ld={} {}",
                        i,
                        theme.address(e.l_addr),
                        theme.address(e.l_ld),
                        name_str
                    );
                }
            }
            Err(e) => {
                eprintln!("failed to read rtld link_map via /proc/{}/mem: {}", args.pid, e);
            }
        }
    }

    if args.binding {
        match binding::summarize_bindings(args.pid) {
            Ok(summaries) => {
                println!("binding summary:");
                for s in summaries {
                    if let Some(ref needle) = args.filter {
                        if !s.name.contains(needle) {
                            continue;
                        }
                    }
                    if args.elf_only {
                        let is_elf = std::fs::read(&s.name)
                            .ok()
                            .map(|b| b.len() >= 4 && b[0..4] == [0x7f, b'E', b'L', b'F'])
                            .unwrap_or(false);
                        if !is_elf {
                            continue;
                        }
                    }

                    println!(
                        "  base={} jmp_slots={} unresolved={} resolved={} unknown={} {}",
                        theme.address(s.base),
                        s.jump_slots,
                        s.unresolved,
                        s.resolved,
                        s.unknown,
                        theme.path(&s.name)
                    );
                }
            }
            Err(e) => {
                eprintln!("failed to summarize bindings via /proc/{}/mem: {}", args.pid, e);
            }
        }
    }
}
