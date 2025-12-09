use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Read;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "wordfreq", about = "Count word frequency in text")]
struct Args {
    #[arg(help = "Text to analyze (or use stdin)")]
    text: Option<String>,

    #[arg(short = 'n', long, default_value_t = 10, help = "Show top N words")]
    top: usize,

    #[arg(
        short = 'm',
        long,
        default_value_t = 1,
        help = "Ignore words shorter than N"
    )]
    min_length: usize,

    #[arg(long, help = "Case insensitive counting")]
    ignore_case: bool,
}

fn main() {
    let args = Args::parse();

    let mut t = String::new();

    if let Some(text_arg) = args.text {
        if Path::new(&text_arg).is_file() {
            //verifie si c'est un fichier
            t = fs::read_to_string(&text_arg).expect("Impossible de lire le fichier");
        } else {
            t = text_arg;
        }
    } else {
        io::stdin()
            .read_to_string(&mut t)
            .expect("Erreur lors de la lecture depuis stdin");
    };

    if args.ignore_case {
        t = t.to_lowercase();
    }

    let mut compteur: HashMap<String, u32> = HashMap::new();
    for mot in t.split_whitespace() {
        //decoupe le texte en mot
        let mot = mot.to_string();
        if mot.chars().all(|c| c == '"' || c == '\'') && !mot.is_empty() {
            continue;
        }
        if mot.is_empty() || mot.len() < args.min_length {
            continue; // ignore les chaînes vides ou trop petites
        }

        let count = compteur.entry(mot).or_insert(0); // si le mot n'existe pas encore on le met avec une valeure de 0
        *count += 1; //* pour acceder a la valeure reelle
    }

    //on convertie la map pour pouvoir la trier
    let mut frequence: Vec<_> = compteur.into_iter().collect(); //tri
    frequence.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (mot, count) in frequence.into_iter().take(args.top) {
        println!("{}: {}", mot, count);
    }
}
