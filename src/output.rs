use std::io::IsTerminal;

/// ansi color goes to terminals (or anything with a pty), never to pipes,
/// unless the caller explicitly opted in or out.
pub fn color_enabled(no_color_flag: bool) -> bool {
    if no_color_flag {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

pub fn paint(s: &str, code: &str, on: bool) -> String {
    if on {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub const HIGH: &str = "1;31";
pub const MEDIUM: &str = "1;33";
pub const INFO: &str = "36";
