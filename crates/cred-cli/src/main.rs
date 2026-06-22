mod commands;
mod util;
mod simple;
mod key;
mod record;
mod vault;
mod grant;
mod presentation;
mod adapters;
mod service;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;
use commands::{Cli, Command};

fn main() -> Result<()> {
    let Cli { store, command } = Cli::parse();
    match command {
        Command::Manifest(command) => simple::print_manifest(command),
        Command::Inspect(path) => simple::inspect(path.path),
        Command::Hash(path) => simple::hash(path.path),
        Command::Verify(path) => simple::verify(path.path),
        Command::Key { command } => key::key(command, store),
        Command::Witness { command } => adapters::witness(command, store),
        Command::Freebird { command } => adapters::freebird(command, store),
        Command::Matchlock { command } => adapters::matchlock(command, store),
        Command::SocialGraph { command } => adapters::social_graph(command, store),
        Command::Record { command } => record::record(command, store),
        Command::Vault { command } => vault::vault(command, store),
        Command::Grant { command } => grant::grant(command, store),
        Command::Present(command) => presentation::present(command, store),
        Command::Serve { command } => service::serve(command, store),
    }
}
