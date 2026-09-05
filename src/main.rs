//! `mlab-mikrotik` — a CLI over the RouterOS REST API.
//!
//! Layout:
//!
//! | module     | role                                                        |
//! | ---------- | ----------------------------------------------------------- |
//! | `ros`      | the API: HTTP handler, stored instances                      |
//! | `collect`  | one pass over what the account can read, and what it cannot  |
//! | `checks`   | the graded checks, as pure functions over collected data     |
//! | `enrich`   | everything that leaves this machine, all of it opt-in        |
//! | `snapshot` | the dated record, and the rules for comparing two of them    |
//! | `secrets`  | the fields that never reach the disk                         |
//! | `ui`       | everything the user sees: progress on stderr, rendering      |
//! | `cli`      | the clap surface and the dispatch                            |
//! | `commands` | one module per command                                       |

mod checks;
mod cli;
mod collect;
mod commands;
mod enrich;
mod ros;
mod secrets;
mod snapshot;
mod ui;

use colored::Colorize;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        // A spinner may own a half-drawn line; wipe it before the message.
        ui::restore();
        eprintln!("  {} {e:#}", "✖".red().bold());
        std::process::exit(1);
    }
}
