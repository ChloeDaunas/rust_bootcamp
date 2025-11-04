use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hello")]

struct Args {
    
    #[arg(default_value = "World")]
    name: String,

    #[arg(long)]
    upper:bool,

    #[arg(long, default_value_t = 1)]
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
