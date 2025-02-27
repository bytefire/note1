use std::path::Path;

use clap::{Parser, Subcommand};

use note1::{delete, get, init, list_tags, post, put};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd : Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Initialize note1 instance. This asks for master password and creates
    /// the database file note1.file in the same directory.
    Init,
    /// Lists all the tags in the database and some other info such as number
    /// of records and total number of records.
    List,
    /// Get value associated with the provided <tag>.
    Get {
        /// The tag to get value for
        tag : String,
    },
    /// Add a new tag and value
    Add {
        /// New tag. If it already exists, use update command instead
        tag : String,
        /// New tag's value
        value : String,
    },
    /// Edit an existing tag's value
    Update {
        /// Existing tag whose value you want to update
        tag : String,
        /// The new value
        value : String,
    },
    /// Delete an existing tag and its value
    Delete {
        /// Existing tag to delete along with its value
        tag : String,
    },
}

fn prep_init(password : &str) {
    let path = Path::new("./note1.file");
    let exists = path.try_exists().unwrap();
    if exists {
        eprintln!("ERROR: cannot init. Database file {} already exists.", path.to_str().unwrap());
        return;
    }

    init(path.to_str().unwrap(), password);
}

// TODO: allow the app to take full path to file name using an environment variable.
//      default file name is ./note1.file
// TODO: search for ./note1.file in the directory where note1 executable is.
//      by default ./ searches in the directory where the command is run from.
fn main() {
    let cli = Cli::parse();
    let password = rpassword::prompt_password("Enter master password: ").unwrap();

    match cli.cmd {
        Commands::Init => prep_init(&password),
        Commands::List => match list_tags("./note1.file", &password) {
            Ok(lst) => lst.iter().for_each(|t| println!("{t}")),
            Err(e) => println!("HTTP status code: {e}"),
        },
        Commands::Get {tag} => match get("./note1.file", &password, &tag) {
                Ok(v) => println!("tag: {}\nvalue: {}", tag, &v),
                Err(e) => println!("HTTP status code: {}", e),
            },
        Commands::Add { tag, value } => { post("./note1.file", &password, &tag, &value); },
        Commands::Update { tag, value } => { put("./note1.file", &password, &tag, &value); },
        Commands::Delete { tag } => { delete("./note1.file", &password, &tag); },
    }
}
