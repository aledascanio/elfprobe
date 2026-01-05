use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub pathname: Option<String>,
}

impl MapEntry {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn pathname_kind(&self) -> PathnameKind {
        match self.pathname.as_deref() {
            None => PathnameKind::Anonymous,
            Some(p) if p.starts_with('[') => PathnameKind::Special,
            Some(p) if p.ends_with(" (deleted)") => PathnameKind::Deleted,
            Some(_) => PathnameKind::File,
        }
    }

    pub fn normalized_pathname(&self) -> Option<String> {
        match self.pathname.as_deref() {
            None => None,
            Some(p) if p.ends_with(" (deleted)") => Some(p.trim_end_matches(" (deleted)").to_string()),
            Some(p) => Some(p.to_string()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathnameKind {
    Anonymous,
    Special,
    Deleted,
    File,
}

impl fmt::Display for PathnameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathnameKind::Anonymous => write!(f, "anonymous"),
            PathnameKind::Special => write!(f, "special"),
            PathnameKind::Deleted => write!(f, "deleted"),
            PathnameKind::File => write!(f, "file"),
        }
    }
}

pub fn read_proc_maps(pid: u32) -> io::Result<Vec<MapEntry>> {
    let path = format!("/proc/{pid}/maps");
    let contents = fs::read_to_string(path)?;
    parse_proc_maps(&contents)
}

pub fn parse_proc_maps(contents: &str) -> io::Result<Vec<MapEntry>> {
    let mut entries = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = parse_maps_line(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse maps line {}: {} ({})", idx + 1, line, e),
            )
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

pub fn parse_maps_line(line: &str) -> Result<MapEntry, String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return Err(format!("expected >= 5 fields, got {}", fields.len()));
    }

    let (start, end) = parse_range(fields[0])?;
    let perms = fields[1].to_string();
    let offset = u64::from_str_radix(fields[2], 16)
        .map_err(|e| format!("invalid offset {}: {}", fields[2], e))?;

    let (dev_major, dev_minor) = parse_dev(fields[3])?;
    let inode = fields[4]
        .parse::<u64>()
        .map_err(|e| format!("invalid inode {}: {}", fields[4], e))?;

    let pathname = if fields.len() > 5 {
        Some(fields[5..].join(" "))
    } else {
        None
    };

    Ok(MapEntry {
        start,
        end,
        perms,
        offset,
        dev_major,
        dev_minor,
        inode,
        pathname,
    })
}

fn parse_range(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("invalid address range: {}", s))?;

    let start = u64::from_str_radix(a, 16).map_err(|e| format!("invalid start {}: {}", a, e))?;
    let end = u64::from_str_radix(b, 16).map_err(|e| format!("invalid end {}: {}", b, e))?;

    Ok((start, end))
}

fn parse_dev(s: &str) -> Result<(u32, u32), String> {
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid dev: {}", s))?;

    let major = u32::from_str_radix(a, 16).map_err(|e| format!("invalid dev major {}: {}", a, e))?;
    let minor = u32::from_str_radix(b, 16).map_err(|e| format!("invalid dev minor {}: {}", b, e))?;

    Ok((major, minor))
}

#[derive(Clone, Debug)]
pub struct MappingGroup {
    pub key: String,
    pub kind: PathnameKind,
    pub entries: Vec<MapEntry>,
}

impl MappingGroup {
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size()).sum()
    }

    pub fn load_bias_candidate(&self) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.offset == 0)
            .map(|e| e.start)
    }

    pub fn has_offset0(&self) -> bool {
        self.entries.iter().any(|e| e.offset == 0)
    }

    pub fn likely_elf_dso(&self) -> bool {
        if self.kind != PathnameKind::File {
            return false;
        }
        if !self.has_offset0() {
            return false;
        }
        self.entries.iter().any(|e| e.perms.contains('x'))
    }

    pub fn elf_magic_ok(&self) -> bool {
        if self.kind != PathnameKind::File {
            return false;
        }
        is_elf_file(Path::new(&self.key)).unwrap_or(false)
    }
}

pub fn group_mappings(entries: &[MapEntry]) -> Vec<MappingGroup> {
    let mut by_key: BTreeMap<(PathnameKind, String), Vec<MapEntry>> = BTreeMap::new();

    for e in entries {
        let kind = e.pathname_kind();
        let key = match kind {
            PathnameKind::Anonymous => "<anonymous>".to_string(),
            PathnameKind::Special => e.pathname.clone().unwrap_or_else(|| "<special>".to_string()),
            PathnameKind::Deleted | PathnameKind::File => e
                .normalized_pathname()
                .unwrap_or_else(|| "<unknown>".to_string()),
        };
        by_key.entry((kind, key)).or_default().push(e.clone());
    }

    by_key
        .into_iter()
        .map(|((kind, key), mut group_entries)| {
            group_entries.sort_by_key(|e| e.start);
            MappingGroup {
                key,
                kind,
                entries: group_entries,
            }
        })
        .collect()
}

fn is_elf_file(path: &Path) -> io::Result<bool> {
    let p: PathBuf = path.into();
    if p.as_os_str().is_empty() {
        return Ok(false);
    }

    let bytes = fs::read(&p);
    let Ok(bytes) = bytes else {
        return Ok(false);
    };

    Ok(bytes.len() >= 4 && bytes[0..4] == [0x7f, b'E', b'L', b'F'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_with_path() {
        let line = "7f2c2c000000-7f2c2c021000 r--p 00000000 08:01 262539 /usr/lib/x86_64-linux-gnu/libdl-2.31.so";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.start, 0x7f2c2c000000);
        assert_eq!(e.end, 0x7f2c2c021000);
        assert_eq!(e.perms, "r--p");
        assert_eq!(e.offset, 0);
        assert_eq!(e.dev_major, 0x08);
        assert_eq!(e.dev_minor, 0x01);
        assert_eq!(e.inode, 262539);
        assert_eq!(e.pathname.as_deref(), Some("/usr/lib/x86_64-linux-gnu/libdl-2.31.so"));
        assert_eq!(e.pathname_kind(), PathnameKind::File);
    }

    #[test]
    fn parse_line_without_path() {
        let line = "55f3b3d9c000-55f3b3dbd000 r--p 00000000 00:00 0";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.pathname, None);
        assert_eq!(e.pathname_kind(), PathnameKind::Anonymous);
    }

    #[test]
    fn parse_line_deleted() {
        let line = "7f2c2c021000-7f2c2c022000 r--p 00021000 08:01 262539 /tmp/libfoo.so (deleted)";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.pathname_kind(), PathnameKind::Deleted);
        assert_eq!(e.normalized_pathname().as_deref(), Some("/tmp/libfoo.so"));
    }

    #[test]
    fn grouping_special_and_file() {
        let entries = vec![
            parse_maps_line("1000-2000 r--p 00000000 00:00 0 [heap]").unwrap(),
            parse_maps_line("2000-3000 r-xp 00000000 08:01 1 /lib/libc.so.6").unwrap(),
            parse_maps_line("3000-4000 r--p 00001000 08:01 1 /lib/libc.so.6").unwrap(),
        ];

        let groups = group_mappings(&entries);
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|g| g.key == "[heap]" && g.kind == PathnameKind::Special));
        assert!(groups.iter().any(|g| g.key == "/lib/libc.so.6" && g.entries.len() == 2));
    }
}
