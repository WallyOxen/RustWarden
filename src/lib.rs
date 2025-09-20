use clap::{Arg, Command};

mod commands;
mod helpers;

use commands::{dump, list_interfaces};

pub struct RustWarden;

impl RustWarden {
    fn cli() -> Command {
        Command::new("RustWarden")
            .about("A mini IDS/IPS implemented in Rust")
            .subcommand_required(true)
            .arg_required_else_help(true)
            .subcommand(
                Command::new("list")
                    .about("List all interfaces")
                    .short_flag('l'),
            )
            .subcommand(
                Command::new("dump")
                    .about("Packet dump")
                    .short_flag('d')
                    .arg_required_else_help(true)
                    .arg(Arg::new("Network Interface")),
            )
    }

    pub fn run() -> Result<(), String> {
        let matches = RustWarden::cli().get_matches();

        match matches.subcommand() {
            Some(("list", _)) => list_interfaces(),
            Some(("dump", sub_matches)) => {
                // Unwrap is okay here becuase clap forces there to be an arg, otherwise it displays the help text for the command
                let network_interface = sub_matches.get_one::<String>("Network Interface").unwrap();

                dump(network_interface)
            }
            _ => unreachable!(),
        }
    }
}
