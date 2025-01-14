use clap::{Parser, Subcommand};

use note1::post;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd : Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Get all tags and values
    Get {
        tag : String,
    },
    /// Add a new tag and value
    Post {
        tag : String,
        value : String,
    },
    /// Edit an existing tag's value
    Put {
        tag : String,
        value : String,
    },
    /// Delete an existing tag and its value
    Delete {
        tag : String,
    },
}
// TODO: allow the app to take full path to file name using an environment variable.
//      default file name is ./note1.file
// TODO: search for ./note1.file in the directory where note1 executable is.
//      by default ./ searches in the directory where the command is run from.
fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Get {tag} => println!("GET /{}", tag),
        Commands::Post { tag, value } => { post("./note1.file", &tag, &value); },
        Commands::Put { tag, value } => println!("PUT /{}\n{}", tag, value),
        Commands::Delete { tag } => println!("DELETE /{}", tag),
    }
}
