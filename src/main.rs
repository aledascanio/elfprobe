
use clap::Parser;

mod maps;
mod proc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Process PID
    #[arg(short, long)]
    pid: u32,
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
    }
}
