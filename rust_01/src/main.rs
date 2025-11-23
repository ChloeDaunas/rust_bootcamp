use clap::Parser;
use std::io;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::io::Read;

#[derive(Parser, Debug)]
#[command(
    name = "wordfreq",
    about = "Count word frequency in text"
)]

struct Args {
    #[arg(), help="Text to analyze (or use stdin)"]
    text: Option<String>,

    #[arg(long, default_value_t = 10, help="Show top N words")]
    top:u8,

    #[arg(long, default_value_t = 1, help="Ignore words shorter than N")]
    min-length: u8,

    #[arg(long, help="Case insensitive counting")]
    ignore_case:bool

}



fn main(){
    let args = Args::parse();
    let mut t=String::new();
    
    if let Some(text_arg) = args.text{
        if Path::new(&text_arg).is_file(){  //verifie si c'est un fichier
            t= fs::read_to_string(&text_arg).expect("Impossible de lire le fichier");
        }
        else {
            t=text_arg;
        
        }
    }
    
    else{
        
        io::stdin().read_to_string(&mut t).expect("Erreur de lecture");
        
    };

    if args.ignore_case{
        t=t.to_lowercase();
    }
    

    let mut compteur: HashMap<String, u32> = HashMap::new();
    for mot in t.split_whitespace() { //decoupe le texte en mot
        let mot = mot.trim_matches(|c: char| !c.is_alphanumeric()).to_string(); //trim enlève des trucs au debut et a 
        // la fin "match" pour enlever un carac particulier "|c: char|" regarde chaque si chaque char individuelement 
        // n'est pas une lettre ou un chiffre
        if mot.is_empty() || mot.len()<args.min_length as usize{
            continue; // ignore les chaînes vides ou trop petites
        }
        
        let count = compteur.entry(mot).or_insert(0); // si le mot n'existe pas encore on le met avec une valeure de 0
        *count += 1; //* pour acceder a la valeure reelle
    }

    //on convertie la map pour pouvoir la trier
    let mut frequence: Vec<(_, _)> = compteur.iter().collect();
    //tri
    frequence.sort_by(|a, b| b.1.cmp(a.1));


    let mut i=0;
    println!("Word frequency");
    for (mot, count) in frequence.iter(){
        println!("{} : {}", mot,count); //affichage
        i+=1;
        if i==args.top{
            break;
        }
    }

}