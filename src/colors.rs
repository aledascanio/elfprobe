pub struct Theme {
    enabled: bool,
}

impl Theme {
    pub fn new(enabled: bool) -> Self {
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
    Reset,
}

impl Color {
    fn code(self) -> &'static str {
        match self {
            Color::Red => "\x1b[31m",
            Color::Yellow => "\x1b[33m",
            Color::Blue => "\x1b[34m",
            Color::Reset => "\x1b[0m",
        }
    }
}
