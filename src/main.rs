use clap::Parser;

mod auxv;
mod colors;
mod demangle;
mod elf64;
mod maps;
mod mem;
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

    /// When to emit ANSI colors (also honors the NO_COLOR env var in `auto`)
    #[arg(long, value_enum, default_value_t = colors::ColorWhen::Auto)]
    color: colors::ColorWhen,

    /// Print per-object PLT relocation symbols (noisy)
    #[arg(long, default_value_t = false)]
    symbols: bool,

    /// Print rtld link_map (with --verbose, also each object's DT_NEEDED/DT_RUNPATH/DT_SONAME)
    #[arg(long, default_value_t = false)]
    rtld: bool,

    /// Include non-ELF mappings in the output
    #[arg(long, default_value_t = false)]
    show_non_elf: bool,

    /// Show extra low-level columns/fields (VMA entry counts, hex sizes, l_ld, ...)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Filter by pathname
    #[arg(long)]
    filter: Option<String>,

    /// Max symbols to print
    #[arg(long)]
    max_symbols: Option<usize>,

    /// Watch GOT slot changes live to observe first-time PLT bindings (requires /proc/<pid>/mem)
    #[arg(long, default_value_t = false)]
    watch: bool,

    /// Polling interval for --watch, in milliseconds
    #[arg(long, default_value_t = 500, requires = "watch")]
    interval_ms: u64,

    /// Number of --watch polling iterations (omit to run forever)
    #[arg(long, requires = "watch")]
    iterations: Option<u64>,
}

fn main() {
    let args = Args::parse();

    let theme = colors::Theme::resolve(args.color);

    match proc::read_exe_info(args.pid) {
        Ok(info) => {
            if let Some(elf) = info.elf {
                let class = match elf.class {
                    proc::ElfClass::Elf32 => "ELF32",
                    proc::ElfClass::Elf64 => "ELF64",
                };
                // Default shows the security-relevant PIE label; --verbose also
                // shows the raw ET_* type.
                let kind = if args.verbose {
                    format!("{} [{}]", elf.pie_label(), elf.type_name())
                } else {
                    elf.pie_label().to_string()
                };
                println!(
                    "exe: {} ({} {:?} {} {})",
                    theme.path(&info.path.display().to_string()),
                    class,
                    elf.endian,
                    kind,
                    elf.machine_name()
                );
            } else {
                println!(
                    "exe: {} {}",
                    theme.path(&info.path.display().to_string()),
                    theme.dim("(non-ELF or unreadable)")
                );
            }
        }
        Err(e) => {
            println!("exe: {}", theme.dim(&format!("<unavailable> ({})", e)));
        }
    }

    let entries = match maps::read_proc_maps(args.pid) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to read /proc/{}/maps: {}", args.pid, e);
            std::process::exit(1);
        }
    };

    if args.watch {
        if let Err(e) = watch::watch_bindings(
            args.pid,
            entries.clone(),
            args.interval_ms,
            args.iterations,
            args.filter.clone(),
            args.show_non_elf,
            args.color,
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

    println!(
        "pid {}: {} map entries, {} groups",
        args.pid,
        entries.len(),
        groups.len()
    );
    let mut header_printed = false;
    for g in groups {
        if !args.show_non_elf {
            // `elf_magic_ok()` touches the mapped file on disk.
            // On large processes this can be very expensive if done for every file-backed mapping.
            // Prefilter using in-memory heuristics so we only probe mappings that look like real DSOs.
            if !(g.kind == maps::PathnameKind::File && g.likely_elf_dso() && g.elf_magic_ok()) {
                continue;
            }
        }
        if let Some(ref needle) = args.filter {
            if !g.key.contains(needle) {
                continue;
            }
        }

        let is_elf =
            g.kind == maps::PathnameKind::File && g.likely_elf_dso() && g.elf_magic_ok();

        // Load base (the offset-0 mapping start) and RELRO state. Both only
        // apply to real ELF DSOs; for non-ELF groups shown via --show-non-elf
        // they are left blank.
        let base_str = match (is_elf, g.load_bias_candidate()) {
            (true, Some(b)) => theme.wrap(
                colors::Color::Yellow,
                &format!("{:>14}", format!("0x{:x}", b)),
            ),
            _ => theme.dim(&format!("{:>14}", "-")),
        };
        let relro_str = if is_elf {
            match elf64::read_relro_status(std::path::Path::new(&g.key)) {
                Ok(elf64::RelroStatus::Full) => {
                    theme.good(&format!("{:<7}", elf64::RelroStatus::Full.label()))
                }
                Ok(elf64::RelroStatus::Partial) => {
                    theme.warn(&format!("{:<7}", elf64::RelroStatus::Partial.label()))
                }
                Ok(elf64::RelroStatus::None) => {
                    theme.bad(&format!("{:<7}", elf64::RelroStatus::None.label()))
                }
                Err(_) => theme.dim(&format!("{:<7}", "-")),
            }
        } else {
            theme.dim(&format!("{:<7}", "-"))
        };

        if !header_printed {
            let header = if args.verbose {
                format!(
                    "{:<9} {:>14} {:>4} {:>10} {:>10} {:<14} {:<7}  {}",
                    "KIND", "BASE", "ENT", "SIZE", "HUMAN", "PERMS", "RELRO", "PATH"
                )
            } else {
                format!("{:<9} {:>14} {:>10} {:<14} {:<7}  {}", "KIND", "BASE", "SIZE", "PERMS", "RELRO", "PATH")
            };
            println!("{}", theme.dim(&header));
            header_printed = true;
        }

        let kind = if is_elf { "elf" } else { &g.kind.to_string() };

        let key = if g.kind == maps::PathnameKind::File {
            theme.path(&g.key)
        } else {
            g.key.clone()
        };
        // Highlight the permission cell in red when any single segment is
        // writable+executable (W^X violation); leave it plain otherwise.
        let perms_padded = format!("{:<14}", g.perm_summary());
        let perms = if g.has_wx() {
            theme.wrap(colors::Color::Red, &perms_padded)
        } else {
            perms_padded
        };
        let size = g.total_size();
        if args.verbose {
            println!(
                "{:<9} {} {:>4} {:>10} {:>10} {} {}  {}",
                kind,
                base_str,
                g.entries.len(),
                format!("0x{:x}", size),
                maps::human_size(size),
                perms,
                relro_str,
                key,
            );
        } else {
            println!(
                "{:<9} {} {:>10} {} {}  {}",
                kind,
                base_str,
                maps::human_size(size),
                perms,
                relro_str,
                key
            );
        }

        if args.symbols && is_elf {
            print_plt_relocations(&g, args.max_symbols, &theme, symbolizer.as_mut());
        }
    }

    if args.rtld {
        let aux = match auxv::read_auxv(args.pid) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("failed to read /proc/{}/auxv: {}", args.pid, e);
                return;
            }
        };
        let mem = match mem::MemReader::open(args.pid) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("failed to open /proc/{}/mem: {}", args.pid, e);
                return;
            }
        };

        match rtld::read_link_map_with_mem(&aux, &mem) {
            Ok(entries) => {
                println!("rtld link_map:");
                for (i, e) in entries.iter().enumerate() {
                    let name = if e.l_name.is_empty() { "<main>" } else { &e.l_name };
                    if !maps::should_include(name, args.filter.as_deref(), args.show_non_elf) {
                        continue;
                    }

                    let name_str = if name.starts_with('/') {
                        theme.path(name)
                    } else {
                        name.to_string()
                    };
                    if args.verbose {
                        println!(
                            "  [{}] base={} l_ld={} {}",
                            i,
                            theme.address(e.l_addr),
                            theme.address(e.l_ld),
                            name_str
                        );
                    } else {
                        println!("  [{}] base={} {}", i, theme.address(e.l_addr), name_str);
                    }

                    if args.verbose {
                        match rtld::read_dynamic_deps(&mem, e) {
                            Ok(d) => {
                                if let Some(soname) = d.soname {
                                    println!("      soname: {}", theme.symbol(&soname));
                                }
                                if let Some(runpath) = d.runpath {
                                    println!("      runpath: {}", runpath);
                                }
                                if let Some(rpath) = d.rpath {
                                    println!("      rpath: {}", rpath);
                                }
                                if !d.needed.is_empty() {
                                    println!("      needed:");
                                    for n in d.needed {
                                        println!("        - {}", theme.symbol(&n));
                                    }
                                }
                            }
                            Err(err) => {
                                println!(
                                    "      dynamic: {}",
                                    theme.dim(&format!("<unavailable> ({})", err))
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "failed to read rtld link_map via /proc/{}/mem: {}",
                    args.pid, e
                );
            }
        }
    }
}

/// Print the PLT relocation entries for an ELF mapping group (the body of
/// `--symbols`). `symbolizer` is used to name IRELATIVE resolver targets.
fn print_plt_relocations(
    g: &maps::MappingGroup,
    max_symbols: Option<usize>,
    theme: &colors::Theme,
    mut symbolizer: Option<&mut symbolize::Symbolizer>,
) {
    use std::path::Path;

    let map0 = g.entries.iter().find(|e| e.offset == 0);
    let load_bias = map0
        .and_then(|m| elf64::compute_load_bias_from_mapping(Path::new(&g.key), m.start, m.offset).ok())
        .or_else(|| g.load_bias_candidate());

    let rels = match elf64::parse_x86_64_plt_relocations(Path::new(&g.key), load_bias) {
        Ok(rels) => rels,
        Err(e) => {
            println!("  plt-relocs: {}", theme.dim(&format!("<unavailable> ({})", e)));
            return;
        }
    };

    if rels.is_empty() {
        return;
    }

    let total = rels.len();
    println!("  plt-relocs: {}", total);
    let max = max_symbols.unwrap_or(total);
    let mut printed = 0usize;

    for r in rels.into_iter().take(max) {
        let got_str = if let Some(addr) = r.got_runtime_addr {
            theme.address(addr)
        } else {
            theme.dim("<unknown>")
        };

        match r.kind {
            elf64::PltRelocationKind::JumpSlot { sym_name } => {
                println!("    got={} JUMP_SLOT {}", got_str, theme.symbol(&sym_name));
            }
            elf64::PltRelocationKind::GlobDat { sym_name } => {
                println!("    got={} GLOB_DAT  {}", got_str, theme.symbol(&sym_name));
            }
            elf64::PltRelocationKind::IRelative {
                resolver_runtime_addr,
            } => {
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
                        println!("    got={} IRELATIVE resolver={}", got_str, theme.address(res));
                    }
                } else {
                    println!(
                        "    got={} IRELATIVE resolver={}",
                        got_str,
                        theme.dim("<unknown>")
                    );
                }
            }
            elf64::PltRelocationKind::Other { sym_name } => {
                if let Some(sym) = sym_name {
                    println!("    got={} type={} {}", got_str, r.r_type, theme.symbol(&sym));
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
