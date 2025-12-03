use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hello", about = "Greet someone")]
struct Args {
    #[arg(default_value = "World", help = "Name to greet")]
    name: String,

    #[arg(short = 'u', long, help = "Convert to uppercase")]
    upper: bool,

    #[arg(
        short = 'r',
        long,
        default_value_t = 1,
        help = "Repeat greeting N times"
    )]
    repeat: u8,
}

fn main() {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(_) => {
            println!("error");
            std::process::exit(2);
        }
    };

    let mut greeting = if args.repeat > 1 {
        args.name.to_string()
    } else {
        format!("Hello, {}!", args.name)
    };

    if args.upper {
        greeting = greeting.to_uppercase();
    }

    for _ in 0..args.repeat {
        println!("{}", greeting);
    }
}
