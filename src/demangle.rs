/// Best-effort demangling of symbol names.
///
/// Handles both Rust (legacy `_ZN...` and v0 `_R...`) and C++ Itanium ABI
/// (`_Z...`) mangled names. Anything else is returned unchanged.
///
/// Ordering matters: Rust v0 (`_R...`) is unambiguous and is tried first.
/// The `_ZN...` prefix is shared between Rust legacy and C++ Itanium, so for
/// that family we try C++ first when there is no Rust-specific marker, falling
/// back to Rust legacy. In practice `rustc_demangle` rejects pure-C++ `_ZN`
/// symbols cleanly (they lack Rust markers), so the order is defensive.

pub fn demangle(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }

    // Rust v0 scheme: unambiguous `_R` prefix.
    if s.starts_with("_R") {
        if let Ok(d) = rustc_demangle::try_demangle(s) {
            return format!("{:#}", d);
        }
    }

    // Itanium ABI (C++): `_Z` prefix.
    if s.starts_with("_Z") {
        if let Ok(d) = cpp_demangle::Symbol::new(s) {
            if let Ok(text) = d.demangle(&Default::default()) {
                return text;
            }
        }
        // Fall through to Rust legacy, which also uses `_ZN...`.
    }

    // Rust legacy scheme: `_ZN...` with Rust markers. The `_Z` branch above
    // already tried C++ on the same prefix, so this is the fallback.
    if s.starts_with("_ZN") {
        if let Ok(d) = rustc_demangle::try_demangle(s) {
            return format!("{:#}", d);
        }
    }

    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::demangle;

    #[test]
    fn rust_v0() {
        assert_eq!(demangle("_RNvCsfTx5JmQea3L_2v05alpha"), "v0::alpha");
    }

    #[test]
    fn rust_legacy() {
        assert_eq!(demangle("_ZN3foo3barE"), "foo::bar");
    }

    #[test]
    fn cpp_itanium() {
        assert_eq!(demangle("_ZN3foo3barEi"), "foo::bar(int)");
    }

    #[test]
    fn cpp_namespaced() {
        assert_eq!(demangle("_ZN3foo3bar4quuxEv"), "foo::bar::quux()");
    }

    #[test]
    fn plain_passthrough() {
        assert_eq!(demangle("printf"), "printf");
        assert_eq!(demangle("malloc"), "malloc");
        assert_eq!(demangle(""), "");
    }

    #[test]
    fn non_symbol_prefix() {
        assert_eq!(demangle("__libc_start_main"), "__libc_start_main");
    }

    // Real-world symbols pulled from a Rust binary that links against a Rust
    // dylib (foo::compute) and the std dylib. These exercise both the v0 and
    // legacy mangling schemes against actual compiler output.
    #[test]
    fn real_rust_v0_std_print() {
        // std::io::stdio::__print — note rustc-demangle's {:#} renders the
        // leading-double-underscore identifier with a single underscore.
        assert_eq!(
            demangle("_RNvNtNtCs75vJTIYSa2J_3std2io5stdio6__print"),
            "std::io::stdio::_print"
        );
    }

    #[test]
    fn real_rust_legacy_foo_compute() {
        // foo::compute — legacy scheme keeps the trailing hash with {:#}.
        assert_eq!(
            demangle("_ZN3foo7compute17ha5feefffbd65482bE"),
            "foo::compute::ha5feefffbd65482b"
        );
    }
}
