use clap::Parser;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Parser, Debug)]
#[command(name = "hextool", about = "Read and write binary files in hexadecimal")]
struct Args {
    /// Target file
    #[arg(short = 'f', long)]
    file: Option<String>,

    /// Read mode (display hex)
    #[arg(short = 'r', long)]
    read: bool,

    /// Write mode (hex string to write)
    #[arg(short = 'w', long)]
    write: Option<String>,

    /// Offset in bytes (decimal or 0x hex)
    #[arg(short = 'o', long)]
    offset: Option<String>,

    /// Number of bytes to read
    #[arg(short = 's', long)]
    size: Option<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //pour renvoyer n'importe quelle erreur
    let args = Args::parse();

    // Vérifier qu'un fichier a été donné
    let file_path;
    if let Some(path) = args.file {
        file_path = path;
    } else {
        println!("Pas de fichier détecté");
        return Ok(());
    }

    // Offset
    let offset: u64 = if let Some(off) = args.offset {
        convertoff(off)?
    } else {
        0
    };

    // read
    if args.read {
        let size = args.size.unwrap_or(128); // recupere la valeur de l'utilisateur ou met 128 par defauts
        lire_file(&file_path, offset, size)?;
    }

    // write
    if let Some(hex_string) = args.write {
        ecrire_file(&file_path, &hex_string, offset)?;
    }

    Ok(())
}

pub fn lire_file(
    file_path: &str,
    offset: u64,
    size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?; //on ouvre le fichier

    file.seek(SeekFrom::Start(offset))?; //on se met a l'offset demandé

    let mut buffer = vec![0u8; size]; //on cree un tableau initialisé a 0 (0u8)
    let bytes_read = file.read(&mut buffer)?; //met les octets lu dans le tableau et compte cb sont lus

    for (i, chunk) in buffer[..bytes_read].chunks(16).enumerate() {
        // Parcourt les octets lus (buffer[..bytes_read]) par "morceaux" de 16 octets
        // i = numéro du chunk (0, 1, 2…)
        // chunk = morceau contenant jusqu’à 16 octets
        let current_offset = offset + (i * 16) as u64; //calcule là ou on en est

        // OFFSET
        print!("{:08x}: ", current_offset); //pour afficher sur 8 chiffres

        // HEXA
        for byte in chunk {
            print!("{:02x} ", byte); //pour afficher sur 2 chiffres
        }

        // Compléter si moins de 16 octets
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }

        print!("|");

        // ASCII
        for byte in chunk {
            let c = *byte as char;
            if c.is_ascii_graphic() || c.is_ascii_whitespace() {
                print!("{}", c);
            } else {
                print!(".");
            }
        }
        println!("|");
    }

    Ok(())
}

pub fn ecrire_file(
    file_path: &str,
    hex_string: &str,
    offset: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = hex_to_bytes(hex_string)?; //on convertis

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;
    //ouvre le fichier           //autorise écriture  //cree le fichier si il n'existe pas

    file.seek(SeekFrom::Start(offset))?; //on va au bon offset

    file.write_all(&bytes)?; //ecrire

    // Affichage le nombre de bytes et l'offset (groupe de 8)
    println!("Writing {} bytes at offset 0x{:08x}", bytes.len(), offset);

    print!("Hex:  ");
    for b in &bytes {
        //ecrit les bytes par deux
        print!("{:02x} ", b);
    }
    println!();

    print!("ASCII: ");

    for &b in &bytes {
        let c = b as char;
        if c.is_ascii_graphic() || c.is_ascii_whitespace() {
            print!("{}", c);
        } else {
            print!(".");
        }
    }
    println!("\nSuccessfully written");

    Ok(())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let clean = hex.trim(); //enleves les espaces au debut et a la fin

    if !clean.len().is_multiple_of(2) {
        //la chaine dois etre paire
        return Err("La chaine dois avoir un nombre pair de char".into());
    }

    let mut bytes = Vec::new();

    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)?; //Pour convertir en nombre en fonction d'une base ici 16
        //De i a i+2
        bytes.push(byte);
    }

    Ok(bytes)
}

fn convertoff(s: String) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim(); //clean

    // hex si commence par 0x sinon decimal
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?) //return
    } else {
        Ok(s.parse::<u64>()?) //convertis la chaine en nombre
    }
}
