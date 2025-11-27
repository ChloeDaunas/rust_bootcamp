use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hello", about = "Greet someone")]
struct Args {
    #[arg(default_value = "World", help = "Name to greet")]
    name: String,

    #[arg(long, help = "Convert to uppercase")]
    upper: bool,

    #[arg(long, default_value_t = 1, help = "Repeat greeting N times")]
    repeat: u8,
}

fn main() {
    let args = Args::parse();

    let greeting = if args.upper {
        format!("HELLO, {}!", args.name.to_uppercase())
    } else {
        format!("Hello, {}!", args.name)
    };

    for _ in 0..args.repeat {
        println!("{}", greeting);
    }
}
