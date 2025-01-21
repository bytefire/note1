use std::path::Path;

use clap::{Parser, Subcommand};

use note1::{get, init, post};

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
        tag : String,
    },
    /// Add a new tag and value
    Add {
        tag : String,
        value : String,
    },
    /// Edit an existing tag's value
    Update {
        tag : String,
        value : String,
    },
    /// Delete an existing tag and its value
    Delete {
        tag : String,
    },
}

fn prep_init() {
    let path = Path::new("./note1.file");
    let exists = path.try_exists().unwrap();
    if exists {
        eprintln!("ERROR: cannot init. Database file {} already exists.", path.to_str().unwrap());
        return;
    }

    let password = rpassword::prompt_password("Enter master password: ").unwrap();

    init(path.to_str().unwrap(), &password);
}

fn prep_add(tag : &str, value : &str) {
    let password = rpassword::prompt_password("Enter master password: ").unwrap();
    post("./note1.file", &password, tag, value);
}
// TODO: allow the app to take full path to file name using an environment variable.
//      default file name is ./note1.file
// TODO: search for ./note1.file in the directory where note1 executable is.
//      by default ./ searches in the directory where the command is run from.
fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init => prep_init(),
        Commands::List => println!("listing..."),
        Commands::Get {tag} => match get("./note1.file", &tag) {
                Ok(v) => println!("tag: {}\nvalue: {}", tag, &v),
                Err(e) => println!("HTTP status code: {}", e),
            },
        Commands::Add { tag, value } => prep_add(&tag, &value),
        Commands::Update { tag, value } => println!("PUT /{}\n{}", tag, value),
        Commands::Delete { tag } => println!("DELETE /{}", tag),
    }
}
