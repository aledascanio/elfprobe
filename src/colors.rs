use std::io::IsTerminal;

pub struct Theme {
    enabled: bool,
}

impl Theme {
    /// Decide whether to emit ANSI colors based on flags and environment:
    /// - `--no-color` (or the `NO_COLOR` env var) always wins and disables color.
    /// - `--colors` forces color on.
    /// - otherwise color is enabled only when stdout is a terminal.
    pub fn resolve(force_on: bool, force_off: bool) -> Self {
        let enabled = if force_off || std::env::var_os("NO_COLOR").is_some() {
            false
        } else if force_on {
            true
        } else {
            std::io::stdout().is_terminal()
        };
        Self { enabled }
    }

    pub fn symbol(&self, s: impl AsRef<str>) -> String {
        self.wrap(Color::Blue, s.as_ref())
    }

    pub fn path(&self, s: impl AsRef<str>) -> String {
        self.wrap(Color::Red, s.as_ref())
    }

    pub fn address(&self, addr: u64) -> String {
        self.wrap(Color::Yellow, &format!("0x{:x}", addr))
    }

    /// De-emphasized text, used for inline status notes like `<unavailable>`
    /// and `<unknown>` that are part of the report but not primary data.
    pub fn dim(&self, s: impl AsRef<str>) -> String {
        self.wrap(Color::Dim, s.as_ref())
    }

    pub fn wrap<'a>(&self, c: Color, s: &'a str) -> String {
        if !self.enabled {
            return s.to_string();
        }
        format!("{}{}{}", c.code(), s, Color::Reset.code())
    }
}

#[derive(Copy, Clone)]
pub enum Color {
    Red,
    Yellow,
    Blue,
    Dim,
    Reset,
}

impl Color {
    fn code(self) -> &'static str {
        match self {
            Color::Red => "\x1b[31m",
            Color::Yellow => "\x1b[33m",
            Color::Blue => "\x1b[34m",
            Color::Dim => "\x1b[2m",
            Color::Reset => "\x1b[0m",
        }
    }
}
