# elfprobe

`elfprobe` is a Linux process inspection tool focused on *ELF dynamic linking state*.

Given a PID, it:

- Groups and summarizes `/proc/<pid>/maps` mappings.
- (Optionally) parses ELF x86_64 PLT relocation entries from mapped DSOs and prints their symbols.
- (Optionally) reads the dynamic loader (`rtld`) `link_map` via `DT_DEBUG` (requires `/proc/<pid>/mem`).
- (Optionally) summarizes “resolved vs unresolved” PLT/GOT bindings by inspecting GOT slots at runtime (requires `/proc/<pid>/mem`).
- (Optionally) polls GOT slots to *watch* first-time PLT bindings happen live (requires `/proc/<pid>/mem`).

This is useful when you want to understand *what a process has mapped*, *which DSOs look like ELF objects*, and *what the dynamic linker is doing with PLT/GOT relocations*.

## Capabilities

- **Mapping inspection**
  - Reads `/proc/<pid>/maps` and groups entries by pathname.
  - Shows mapping group size, number of entries, and heuristics:
    - `likely-elf`: file mapping has an executable segment and an offset-0 mapping.
    - `elf-magic`: file on disk starts with `0x7f 'E' 'L' 'F'`.

- **PLT relocation listing (`--symbols`)**
  - For each ELF-looking file mapping, attempts to parse `.rela.plt` / `DT_JMPREL` entries.
  - Prints per-object PLT relocations (can be noisy).
  - Handles common x86_64 relocation kinds:
    - `R_X86_64_JUMP_SLOT`
    - `R_X86_64_IRELATIVE` (best-effort, may be symbolized)

- **`rtld` link_map dump (`--rtld`)**
  - Uses `/proc/<pid>/auxv` to find `AT_PHDR` / `AT_PHNUM` and then walks the main executable’s program headers in memory.
  - Finds the `DT_DEBUG` pointer, reads `struct r_debug`, then traverses the `link_map` list.

- **Binding summary (`--binding`)**
  - For each entry in `link_map`, parses its PLT relocations and reads each GOT slot value.
  - Classifies a `JUMP_SLOT` relocation as:
    - `unresolved`: GOT points into that object’s PLT range (typical lazy binding state)
    - `resolved`: GOT points elsewhere (already bound)
    - `unknown`: couldn’t determine / couldn’t read

- **Live binding watcher (`--watch-bindings`)**
  - Builds a list of GOT slots for `JUMP_SLOT` relocations and polls them.
  - Prints changes when a slot is updated, optionally symbolizing the new target address.

## Requirements / Notes

- **OS**: Linux (relies on `/proc`).
- **Permissions**:
  - Reading `/proc/<pid>/maps` often works as the same user.
  - Reading `/proc/<pid>/mem` is typically restricted (Yama `ptrace_scope`, permissions, capabilities). You may need to run as root, or attach/allow ptrace, depending on your system.
- **Architecture support**:
  - PLT relocation parsing is currently **x86_64-focused** (expects `e_machine = 62` and `DT_PLTREL = DT_RELA`).
  - Basic mapping grouping works for any process, but the deep ELF/rtld features assume a 64-bit process layout.

## Installation

Build from source:

```bash
cargo build --release
```

The binary will be at:

- `target/release/elfprobe`

## Usage

Basic mapping overview:

```bash
elfprobe --pid <PID>
```

Enable ANSI-colored output:

```bash
elfprobe --pid <PID> --colors
```

`--pid` also has a short form:

```bash
elfprobe -p <PID>
```

Show per-object PLT relocation symbols (noisy):

```bash
elfprobe --pid <PID> --symbols
```

Limit the number of printed symbols per object:

```bash
elfprobe --pid <PID> --symbols --max-symbols 50
```

Filter output by pathname substring:

```bash
elfprobe --pid <PID> --filter libc
```

Only consider mappings that are actual ELF files on disk:

```bash
elfprobe --pid <PID> --elf-only
```

Dump `rtld` `link_map` (requires `/proc/<PID>/mem`):

```bash
elfprobe --pid <PID> --rtld
```

Summarize PLT/GOT binding state (requires `/proc/<PID>/mem`):

```bash
elfprobe --pid <PID> --binding
```

Watch GOT slot changes (polling) (requires `/proc/<PID>/mem`):

```bash
elfprobe --pid <PID> --watch-bindings --interval-ms 200
```

If you omit `--interval-ms`, the default is `500`.

Stop after N iterations:

```bash
elfprobe --pid <PID> --watch-bindings --interval-ms 200 --iterations 100
```

## Output overview

- The initial `exe:` line prints `/proc/<pid>/exe` plus basic ELF header info when readable.
- Mapping groups are printed as:
  - `file /path/to/lib.so entries=N size=0x... likely-elf elf-magic`
- With `--symbols`, per-object PLT relocation entries look like:
  - `got=0x... JUMP_SLOT printf`
  - `got=0x... IRELATIVE resolver=0x... name=...`
- With `--binding`, the summary is:
  - `base=0x... jmp_slots=X unresolved=Y resolved=Z unknown=W /path/to/lib.so`

## Troubleshooting

- **“failed to read /proc/<pid>/mem” / permission denied**
  - `--rtld`, `--binding`, and `--watch-bindings` require `/proc/<pid>/mem` access.
  - On many distros you may need root, or to adjust ptrace restrictions.

- **“unsupported e_machine … (x86_64 expected)”**
  - The PLT relocation parsing is currently implemented for x86_64 only.

- **Missing / empty entries in `--rtld` output**
  - The main executable may appear with an empty name (`<main>`) in `link_map`.
  - Non-path `link_map` entries (e.g. linux-vdso) may be filtered out by `--elf-only`.

## Development

Run tests:

```bash
cargo test
```

Format:

```bash
cargo fmt
```

Show CLI help:

```bash
elfprobe --help
```

## License

MIT (see `LICENSE`).
