use std::io::IsTerminal;

use clap::ValueEnum;

/// When to emit ANSI colors, selected via `--color <auto|always|never>`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorWhen {
    /// Color only when stdout is a terminal (and `NO_COLOR` is unset).
    Auto,
    /// Always color, overriding terminal detection and `NO_COLOR`.
    Always,
    /// Never color.
    Never,
}

pub struct Theme {
    enabled: bool,
}

impl Theme {
    /// Decide whether to emit ANSI colors based on `--color <when>` and env:
    /// - `never` disables color.
    /// - `always` forces color on, overriding terminal detection and `NO_COLOR`.
    /// - `auto` enables color only when stdout is a terminal and `NO_COLOR`
    ///   is unset.
    pub fn resolve(when: ColorWhen) -> Self {
        let enabled = match when {
            ColorWhen::Never => false,
            ColorWhen::Always => true,
            ColorWhen::Auto => {
                std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
            }
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

    /// Good / safe status (e.g. full RELRO).
    pub fn good(&self, s: impl AsRef<str>) -> String {
        self.wrap(Color::Green, s.as_ref())
    }

    /// Warning / risky status (e.g. partial RELRO).
    pub fn warn(&self, s: impl AsRef<str>) -> String {
        self.wrap(Color::Yellow, s.as_ref())
    }

    /// Bad / unsafe status (e.g. no RELRO).
    pub fn bad(&self, s: impl AsRef<str>) -> String {
        self.wrap(Color::Red, s.as_ref())
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
    Green,
    Blue,
    Dim,
    Reset,
}

impl Color {
    fn code(self) -> &'static str {
        match self {
            Color::Red => "\x1b[31m",
            Color::Yellow => "\x1b[33m",
            Color::Green => "\x1b[32m",
            Color::Blue => "\x1b[34m",
            Color::Dim => "\x1b[2m",
            Color::Reset => "\x1b[0m",
        }
    }
}
