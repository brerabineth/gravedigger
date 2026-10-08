use clap::Parser;
use gravedigger::{hashcmd, hunt, strings, sweep, timeline, Ctx};

static ABOUT: &str = "dig through the dirt on a compromised host.\nbuilt for the first hour of an incident, when the clock is the enemy.";

static EXAMPLES: &str = "  gravedigger timeline /mnt/evidence --format body > super_timeline.body
  gravedigger hash /mnt/evidence --against known_bad.txt   # exit 3 on hit
  gravedigger strings /mnt/evidence --utf16 > strings.txt
  gravedigger hunt /mnt/evidence                           # exit 3 on finding
  gravedigger sweep --out /mnt/evidence --profile full";

#[derive(Parser)]
#[command(
    name = "gravedigger",
    version,
    about = ABOUT,
    after_help = EXAMPLES
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// disable ansi color
    #[arg(long, global = true)]
    no_color: bool,

    /// suppress stderr summaries
    #[arg(long, global = true)]
    quiet: bool,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// filesystem timeline in mactime body format
    Timeline(timeline::TimelineArgs),
    /// recursive hashing with known-bad matching
    Hash(hashcmd::HashArgs),
    /// extract ascii and utf-16le strings
    Strings(strings::StringsArgs),
    /// sweep a tree for ransomware IOCs
    Hunt(hunt::HuntArgs),
    /// collect live-response artifacts into a report directory
    Sweep(sweep::SweepArgs),
}

fn main() {
    let cli = Cli::parse();
    let ctx = Ctx {
        color: gravedigger::output::color_enabled(cli.no_color),
        quiet: cli.quiet,
    };

    let rc = match &cli.cmd {
        Cmd::Timeline(a) => timeline::run(a, &ctx),
        Cmd::Hash(a) => hashcmd::run(a, &ctx),
        Cmd::Strings(a) => strings::run(a, &ctx),
        Cmd::Hunt(a) => hunt::run(a, &ctx),
        Cmd::Sweep(a) => sweep::run(a, &ctx),
    };

    std::process::exit(match rc {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gravedigger: {e:#}");
            1
        }
    });
}
