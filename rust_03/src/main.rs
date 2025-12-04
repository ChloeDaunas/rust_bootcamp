use clap::{Parser, Subcommand};
mod dh;
use dh::{G, P};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(
    name = "stramchat",
    about = "Stream Cipher chat with Diffie-Hellman key generation"
)]
struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    //ouvre le serveur
    Server { port: u16 },

    //se connecte au serveur
    Client { address: String },
}

fn generate_keystream(seed: u32) -> Vec<u8> {
    let length = 1024;
    let mut x = seed;
    let mut out = Vec::with_capacity(length);

    for _ in 0..length {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        out.push((x >> 16) as u8);
    }

    let n = out.len().min(14); //pour pas que ça depasse si moins de 14 byte
    println!("Keystream: {:02X?} ...\n", &out[..n]);
    println!("Secure channel established!\n");

    out
}

fn create_public_key(base: u64, exponent: u64, modulo: u64) -> u64 {
    //attention a ce que ça ne depasse pas
    //on doit faire public=G^private mod P

    let mut result = 1u64;
    let mut b = base % modulo; //on passe par le binaire pour pas avoir d'overflow
    let mut e = exponent;

    while e > 0 {
        if e % 2 == 1 {
            result = ((result as u128 * b as u128) % modulo as u128) as u64;
        }

        b = ((b as u128 * b as u128) % modulo as u128) as u64;
        e /= 2;
    }

    result
}

fn encrypter(seed: u32) -> std::io::Result<Vec<u8>> {
    // On génère tout le keystream d’un coup
    let keystream = generate_keystream(seed);

    //prendre le message
    println!("\n[CHAT] Type message:");
    io::stdout().flush().unwrap(); // Force l'affichage avant la saisie 
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Erreur lors de la lecture");
    let message = input.trim();
    let message_bytes = message.as_bytes();

    let mut _ciphertext: std::vec::Vec<u8> = Vec::with_capacity(message.len());

    for (i, &byte) in message_bytes.iter().enumerate() {
        _ciphertext.push(byte ^ keystream[i]);
    }

    println!("\n[ENCRYPT]");
    println!("Plain: {:02X?} (\"{}\")", message.as_bytes(), message);
    println!("Cipher: {:02X?}\n", _ciphertext);

    let mut file = File::create("plain.txt")?; //on garde une trace du message d'origne
    file.write_all(message.as_bytes())?;

    Ok(_ciphertext)
}

fn decrypter(seed: u32, message: &[u8]) -> Vec<u8> {
    // Génération du même keystream
    let keystream = generate_keystream(seed);

    let _first_key = keystream[0];

    // Déchiffrement XOR
    let mut plain: Vec<u8> = Vec::with_capacity(message.len());
    for (i, &byte) in message.iter().enumerate() {
        plain.push(byte ^ keystream[i]);
    }

    println!(
        "Plain: {:02X?} \"{}\"",
        plain,
        String::from_utf8_lossy(&plain)
    );

    plain
}

fn envoyer(stream: &mut TcpStream, message: &[u8]) -> std::io::Result<()> {
    println!(
        "[NETWORK] Sending encrypted message ({} bytes)...",
        message.len()
    );
    println!("Sent {} bytes", message.len());
    let bytes = message;
    let len = bytes.len() as u16;

    // Écrire la longueur en big-endian
    stream.write_all(&len.to_be_bytes())?;

    // Écrire le message
    stream.write_all(bytes)?;

    Ok(())
}

fn recevoir(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    // Lire les 2 octets de longueur
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;

    // Lire le message
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer)?;

    Ok(buffer)
}

fn verifier_secret(stream: &mut TcpStream, shared: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf)?;
    let server_shared = u64::from_be_bytes(buf);
    if server_shared == shared {
        println!("[VERIFY] Both sides computed the same secret\n");
    } else {
        println!("[VERIFY] not the same secret\n");
    }

    Ok(())
}

fn verifier_cryptage(plain: &[u8]) -> std::io::Result<()> {
    let mut file = File::open("plain.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    println!(
        "[TEST] Round-trip verified: \"{}\"-> encrypt -> decrypt -> \"{}\"",
        contents.trim(),
        String::from_utf8_lossy(plain)
    );

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Server { port } => {
            let listener = TcpListener::bind(("0.0.0.0", port))?; //cree un listener qui accepte les connexions
            println!("[SERVER] Listening on {}", port);

            println!("[SERVER] Waiting for client...\n");
            let (mut stream, addr) = listener.accept()?; //bloque jusqu'a ce que une connexion arrive

            //stream pour lire/ecrire vers le client et addr= add ip et port du client
            println!("[CLIENT] Connected from {}\n", addr);

            //creer la private key
            let private: u64 = rand::random();

            let public = create_public_key(G, private, P);
            println!("[DH] Using hardcoded DH parameters:");
            println!("p = {:X} (64-bit prime - public)", P);
            println!("g = {:X} (generator - public)\n", G);

            println!("[DH] Generating our keypair...");
            println!("private key = {:016X} (random 64-bit)", private);
            println!(
                "public key = g^private mod p = 2^{} mod p = {:016X}\n",
                private, public
            );

            //envoyer la public key
            //TCP envoie des octets donc il faut transformer public (u64) en 8 octets
            let public_bytes = public.to_be_bytes(); //be pour que l'octet le plus sygnificatif soit en premier et etre sur que tt le monde lit pareil

            let len = public_bytes.len() as u16;
            stream.write_all(&len.to_be_bytes())?;
            stream.write_all(&public_bytes)?;
            println!("[DH] Exchanging keys...");
            println!("[NETWORK] Sending public key (8 bytes)...");
            println!("Send our public: {:016X}", public);

            //recevoir otherPublicKey
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf)?;
            let len = u16::from_be_bytes(len_buf) as usize;

            //convertir otherPublicKey en byte
            let mut other_bytes = vec![0u8; len];
            stream.read_exact(&mut other_bytes)?;
            let other_public = u64::from_be_bytes(other_bytes.try_into().unwrap());
            println!("[NETWORK] Received public key ({} bytes)", len);
            println!("Receive their public: {:016X}\n", other_public);

            //Calculer shared = mod_pow(other_public, private, P).
            let shared = create_public_key(other_public, private, P);

            //convertir la shared (u64) en u32 pour le LGC
            let graine_lgc = shared as u32;
            println!("[DH] Computing shared secret...");
            println!("Formula: secret = (their_public)^(our_private) mod p\n");
            println!(
                "secret = ({:016X})^({:016X}) mod p = {:016X}\n",
                other_public, private, shared
            );

            stream.write_all(&shared.to_be_bytes())?; //envoie
            let _ = verifier_secret(&mut stream, shared); //reçoit

            //println!("[VERIFY] Both sides computed the same secret ✓");

            println!("[STREAM] Generating keystream from secret...");
            println!("Algorithm: LCG (a=1103515245, c=12345, m=2^32)");
            println!("Seed: secret = {:016X}\n", shared as u32);
            //println!("Keystream: {:02X?}", keystream);

            //crypter le message
            let messagecrypte = encrypter(graine_lgc)?;

            //envoyer message
            envoyer(&mut stream, &messagecrypte)?;

            //recevoir message
            let message_recu = recevoir(&mut stream)?;

            //decripter
            let messagedecryte = decrypter(graine_lgc, &message_recu);

            let _ = verifier_cryptage(&messagedecryte);

            println!("[CLIENT] {}", String::from_utf8_lossy(&messagedecryte));
        }

        Commands::Client { address } => {
            println!("[CLIENT] Connected to {}", address);
            let mut stream = TcpStream::connect(address)?; //le client se connecte au server 
            //renvoie un TcpStream si reussit

            println!("[CLIENT] Connected!\n");
            println!("[DH] Starting key exchange...");

            //creer la private key
            let private: u64 = rand::random();
            let public = create_public_key(G, private, P);

            println!("[DH] Using hardcoded DH parameters:");
            println!("p = {:X} (64-bit prime - public)", P);
            println!("g = {:X} (generator - public)\n", G);

            println!("[DH] Generating our keypair...");
            println!("private_key = {:016X} (random 64-bit)", private);
            println!(
                "public key = g^private mod p = 2^{} mod p = {:016X}\n",
                private, public
            );

            println!("[DH] Exchanging keys...");

            //recevoir otherPublicKey
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf)?;
            let len = u16::from_be_bytes(len_buf) as usize;

            //convertir otherPublicKey en byte
            let mut other_bytes = vec![0u8; len];
            stream.read_exact(&mut other_bytes)?;

            let other_public = u64::from_be_bytes(other_bytes.try_into().unwrap());

            println!("[NETWORK] Received public key ({} bytes)", len);
            println!("Receive their public: {:016X}", other_public);

            //envoyer la public key
            //TCP envoie des octets donc il faut transformer public (u64) en 8 octets
            println!("[NETWORK] Sending public key (8 bytes)...");
            let public_bytes = public.to_be_bytes(); //be pour que l'octet le plus sygnificatif soit en premier et etre sur que tt le monde lit pareil

            let len = public_bytes.len() as u16;
            stream.write_all(&len.to_be_bytes())?;
            stream.write_all(&public_bytes)?;
            println!("Send our public: {:016X}\n", public);

            //Calculer shared = mod_pow(other_public, private, P).
            let shared = create_public_key(other_public, private, P);

            //convertir la shared (u64) en u32 pour le LGC
            let graine_lgc = shared as u32;
            println!("[DH] Computing shared secret...");
            println!("Formula: secret = (their_public)^(our_private) mod p\n");

            println!(
                "secret = ({:016X})^({:016X}) mod p = {:016X}\n",
                other_public, private, shared
            );

            //println!("[VERIFY] Both sides computed the same secret \n");

            let _ = verifier_secret(&mut stream, shared); //reçoit
            stream.write_all(&shared.to_be_bytes())?; //envoie

            println!("[STREAM] Generating keystream from secret...");
            println!("Algorithm: LCG (a=1103515245, c=12345, m=2^32)");
            println!("Seed: secret = {:016X}\n", shared);

            let _ = generate_keystream(graine_lgc);

            //recevoir message
            let message_recu = recevoir(&mut stream)?;
            println!(
                "[NETWORK] Received encrypted message ({} bytes)",
                message_recu.len()
            );
            println!("Received {} bytes\n", message_recu.len());

            //decripter
            println!("[DECRYPT]");
            println!("Cipher: {:02X?}", message_recu);

            let messagedecryte = decrypter(graine_lgc, &message_recu);

            let _ = verifier_cryptage(&messagedecryte); //reçoit
            println!("\n[SERVEUR] {}\n", String::from_utf8_lossy(&messagedecryte));

            //println!("\n[TEST] Round-trip verified: \"{}\" -> encrypt -> decrypt -> \"{}\"",)
            //crypter le message
            let messagecrypte = encrypter(graine_lgc)?;

            //envoyer message
            envoyer(&mut stream, &messagecrypte)?;
        }
    }

    Ok(())
}
