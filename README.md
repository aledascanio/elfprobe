# elfprobe

`elfprobe` is a Linux process inspection tool focused on *ELF dynamic linking state*.

Given a PID, it:

- Groups and summarizes `/proc/<pid>/maps` mappings (ELF files only by default).
- (Optionally) parses ELF x86_64 PLT relocation entries from mapped DSOs and prints their symbols.
- (Optionally) reads the dynamic loader (`rtld`) `link_map` via `DT_DEBUG` (requires `/proc/<pid>/mem`).
- (Optionally) summarizes “resolved vs unresolved” PLT/GOT bindings by inspecting GOT slots at runtime (requires `/proc/<pid>/mem`).
- (Optionally) polls GOT slots to *watch* first-time PLT bindings happen live (requires `/proc/<pid>/mem`).


## Capabilities

- **Mapping inspection**
  - Reads `/proc/<pid>/maps` and groups entries by pathname.
  - Shows mapping group size and number of entries.
  - File mappings that look like loaded ELF DSOs (executable segment, offset-0 mapping, and valid ELF magic on disk) are labeled `elf` instead of `file`.

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


## Usage

Basic mapping overview:

```bash
elfprobe --pid <PID>
```

ANSI colors are enabled automatically when stdout is a terminal. Force them on or off:

```bash
elfprobe --pid <PID> --colors     # force on
elfprobe --pid <PID> --no-color   # force off
```

The `NO_COLOR` environment variable (any value) also disables colors.

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

Include non-ELF mappings in the output (by default only ELF files are shown):

```bash
elfprobe --pid <PID> --show-non-elf
```

Show extra low-level columns/fields (VMA entry counts, hex sizes, `l_ld`, ...):

```bash
elfprobe --pid <PID> --verbose   # or -v
```

Dump `rtld` `link_map` (requires `/proc/<PID>/mem`):

```bash
elfprobe --pid <PID> --rtld
```

Dump `rtld` `link_map` plus `DT_NEEDED` / `DT_RUNPATH` / `DT_SONAME` from each object’s in-memory `PT_DYNAMIC` (implies `--rtld`) (requires `/proc/<PID>/mem`):

```bash
elfprobe --pid <PID> --rtld-deps
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

Show CLI help:

```bash
elfprobe --help
```
## Output overview

- The initial `exe:` line prints `/proc/<pid>/exe` plus basic ELF header info when readable.
- Mapping groups are printed as an aligned table with a `KIND SIZE PATH` header, e.g.:
  - `elf          1.9 MiB  /usr/lib/x86_64-linux-gnu/libc.so.6`
  - With `--verbose` the table gains `ENT` (VMA entry count) and a hex `SIZE` column: `KIND ENT SIZE HUMAN PATH`.
- With `--symbols`, per-object PLT relocation entries look like:
  - `got=0x... JUMP_SLOT printf`
  - `got=0x... IRELATIVE resolver=0x... name=...`
- With `--binding`, the summary is an aligned table with a `BASE SLOTS UNRES RES UNK RESOLVED PATH` header and a `TOTAL` footer, where `RESOLVED` is a bar showing the resolved fraction of jump slots, e.g.:
  - `  0x7f...  15  0  15  0  [##########] 100%  /usr/lib/x86_64-linux-gnu/libc.so.6`
- Sizes are shown as human-readable binary units (KiB/MiB/...); `--verbose` also shows the raw hex size.
- The `--rtld` view shows `l_ld` only with `--verbose`.
- Inline status notes such as `<unavailable>` / `<unknown>` are dimmed when colors are enabled.

## Troubleshooting

- **“failed to read /proc/<pid>/mem” / permission denied**
  - `--rtld`, `--binding`, and `--watch-bindings` require `/proc/<pid>/mem` access.
  - On many distros you may need root, or to adjust ptrace restrictions.

- **“unsupported e_machine … (x86_64 expected)”**
  - The PLT relocation parsing is currently implemented for x86_64 only.

- **Missing / empty entries in `--rtld` output**
  - The main executable may appear with an empty name (`<main>`) in `link_map`.
  - Non-path `link_map` entries (e.g. linux-vdso) are filtered out by default. Use `--show-non-elf` to include them.



## License

MIT (see `LICENSE`).
