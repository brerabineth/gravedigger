pub mod body;
pub mod hashcmd;
pub mod hunt;
pub mod iocs;
pub mod output;
pub mod strings;
pub mod sweep;
pub mod timeline;
pub mod walk;

/// shared run context threaded through every subcommand
pub struct Ctx {
    pub color: bool,
    pub quiet: bool,
}
