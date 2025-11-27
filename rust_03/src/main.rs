use clap::{Parser, Subcommand};
mod dh;
use dh::{P,G};
use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use rand::Rng; 

#[derive(Parser, Debug)]
#[command(
    name = "stramchat",
    about = "Stream Cipher chat with Diffie-Hellman key generation"


)]

struct Args {
    
    #[command(subcommand)]
    pub command: Commands,

    

}

#[derive(Subcommand)]
pub enum Commands{
    //ouvre le serveur
    Server{
        port: u16,
    },

    //se connecte au serveur
    Client{
        address: String,
    },
}

fn CreatePublicKey(base: u64, exponent: u64, modulo:u64)->u64{ //attention a ce que ça ne depasse pas
     //on doit faire public=G^private mod P

            let mut result = 1u64;
            let mut b = base % modulo;  //on passe par le binaire pour pas avoir d'overflow
            let mut e = exponent;


            while e > 0 {
                if e % 2 == 1 {
                    result = (result * b) % modulo;

                }

                b = (b * b) % modulo;
                e /= 2;
            }

            result       
}

fn encrypter(seed: u32) -> Vec<u8> {
    let a = 1103515245u32;
    let c = 12345u32;

    //prendre le message 
    println!("[CHAT] Type message:");
    io::stdout().flush().unwrap(); // Force l'affichage avant la saisie 
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Erreur lors de la lecture"); 
    let message = input.trim() ;
    println!();
    

    let mut state = seed;
    let mut ciphertext = Vec::with_capacity(message.len());

    for &byte in message.as_bytes() {
        // Générer le prochain état du LCG
        //state à n+1=(a*state à n) mod m
        state = state.wrapping_mul(a).wrapping_add(c); //wrapping pour pas que ça depasse
        //m=2^32 donc le mod 32 automatique

        // On prend les 4 octets de l'état en big-endian
        let keystream = state.to_be_bytes();

        // XOR le byte avec un octet du keystream (ici on peut utiliser keystream[0])
        ciphertext.push(byte ^ keystream[0]);
    }

    println!("[ENCRYPT]");
    println!("Plain: {:02X?} (\"{}\")", plain_bytes, message);
    println!("Key: {:02X?} (keystream position: {})", key_bytes, key_bytes.len() - 1);
    println!("Cipher: {:02X?}", ciphertext);

    ciphertext
}

fn decrypter(seed: u32, message: &[u8]) -> Vec<u8> {
    let a = 1103515245u32;
    let c = 12345u32;

    let mut state = seed;
    let mut plain = Vec::with_capacity(message.len());

    for &byte in message {
        // Générer le prochain état du LCG
        //state à n+1=(a*state à n) mod m
        state = state.wrapping_mul(a).wrapping_add(c); //wrapping pour pas que ça depasse
        //m=2^32 donc le mod 32 automatique

        // On prend les 4 octets de l'état en big-endian
        let keystream = state.to_be_bytes();

        // XOR le byte avec un octet du keystream (ici on peut utiliser keystream[0])
        plain.push(byte ^ keystream[0]);
    }

    println!("[DECRYPT]");
    println!("Cipher: {:02X?}", cipher_bytes);
    println!("Key: {:02X?} (keystream position: {})", key_bytes, key_bytes.len() - 1);
    println!("Plain: {:02X?} \"{}\"", plain_bytes, plaintext);

    plain
}

fn envoyer(stream: &mut TcpStream, message: &[u8]) -> std::io::Result<()> {
    println!("[NETWORK] Sending encrypted message ({} bytes)...", message.len());
    println!("[+] Sent {} bytes", message.len());
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

    println!("[NETWORK] Received encrypted message ({} bytes)", buffer.len());
    println!("[+] Received {} bytes", buffer.len());

    
    Ok(buffer)
}



fn main()-> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    

    match args.command {
        Commands::Server { port } => {
            let listener =TcpListener::bind(("0.0.0.0", port))?;//cree un listener qui accepte les connexions
            println!("[SERVER] Listening on {}", port);

            println!("[SERVER] Waiting for client...\n")
            let (mut stream, addr) = listener.accept()?;//bloque jusqu'a ce que une connexion arrive

            //stream pour lire/ecrire vers le client et addr= add ip et port du client
            println!("[CLIENT] Connected from {}\n", addr);

            //creer la private key
            let private: u64 = rand::random();
            let public=CreatePublicKey(G, private, P);
            println!("[OH] Using hardcoded DH parameters:");
            println!("p = {:016X} (64-bit prime - public)", P);
            println!("g = {:X} (generator - public)\n", G);

            println!("[OH] Generating our keypair...");
            println!("private key = {:016X} (random 64-bit)", private);
            println!("public key = g^private mod p = {:016X}\n ", public);
            
            
            //envoyer la public key
            //TCP envoie des octets donc il faut transformer public (u64) en 8 octets
            let public_bytes=public.to_be_bytes(); //be pour que l'octet le plus sygnificatif soit en premier et etre sur que tt le monde lit pareil

            let len = public_bytes.len() as u16;        
            stream.write_all(&len.to_be_bytes())?;      
            stream.write_all(&public_bytes)?;
            println!("[DH] Exchanging keys...");
            println!("[NETWORK] Sending public key (8 bytes)...");
            println!("Send our public: {:016X}", public_bytes);

            
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
            let shared = CreatePublicKey(other_public, private, P);

            //convertir la shared (u64) en u32 pour le LGC
            let graineLGC=shared as u32;
            println!("[DH] Computing shared secret...");
            println!("Formula: secret = (their_public)^(our_private) mod p\n");
            println!("secret = ({:016X})^({:016X}) mod p = {:016X}\n", other_public, private, shared);

            println!("[VERIFY] Both sides computed the same secret ✓");


            println!("[STREAM] Generating keystream from secret...");
            println!("Algorithm: LCG (a=1103515245, c=12345, m=2^32)");
            println!("Seed: secret = {:016X}", shared as u32);
            ???????????????????println!("Keystream: {:02X?}", &keystream[..14]); // 14 bytes comme exemple
            println!("Secure channel established!");

            //crypter le message
            let messagecrypte=encrypter(graineLGC);

            //envoyer message
            envoyer(&mut stream, messagecrypte);

            //recevoir message
            let messagereçu=recevoir(& mut stream);

            //decripter
            let messagedecryte=decrypter(graineLGC,messagereçu);

            println!("[TEST] Round-trip verified: \"{}\" encrypt → decrypt \"{}\"\n",messagereçu, messagedecryte);
            println!("[CLIENT] {}", String::from_utf8_lossy(&messagedecryte));
            
        }

        Commands::Client { address } => {
            println!("[CLIENT] Connected to {}", address);
            let mut stream=TcpStream::connect(address)?; //le client se connecte au server 
            //renvoie un TcpStream si reussit

            
            println!("[CLIENT] Connected!");
            println!("[OH] Starting key exchange...");

            //creer la private key
            let private: u64 = rand::random();
            let public=CreatePublicKey(G, private, P);

            println!("[DH] Using hardcoded DH parameters:");
            println!("p = {:016X} (64-bit prime - public)", P);
            println!("g = {:X} (generator - public)\n", G);

            println!("[DH] Generating our keypair...");
            println!("private_key = {:016X} (random 64-bit)", private);
            println!("public key = g^private mod p = {:016X}\n", public);

    
            println!("[OH] Exchanging keys...");
            println!("[NETWORK] Waiting for server public key...");

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
            let public_bytes=public.to_be_bytes(); //be pour que l'octet le plus sygnificatif soit en premier et etre sur que tt le monde lit pareil

            
            let len = public_bytes.len() as u16;        
            stream.write_all(&len.to_be_bytes())?;      
            stream.write_all(&public_bytes)?;
            println!("Send our public: {:016X}\n", public);
            


            //Calculer shared = mod_pow(other_public, private, P).
            let shared = CreatePublicKey(other_public, private, P);

            //convertir la shared (u64) en u32 pour le LGC
            let graineLGC=shared as u32; 
            println!("[OH] Computing shared secret...");
            println!("Formula: secret = (their_public)^(our_private) mod p");
            println!("secret = ({:016X})^({:016X}) mod p = {:016X}", other_public, private, shared);
            println!("[VERIFY] Both sides computed the same secret ✓\n");

            println!("[STREAM] Generating keystream from secret...");
            println!("Algorithm: LCG (a=1103515245, c=12345, m=2^32)");
            println!("Seed: secret = {:016X}", shared);
            println!("(keystream generated during encryption)");
            println!("Secure channel established!\n");

            //recevoir message
            println!("[NETWORK] Waiting for encrypted message...");
            let messagereçu=recevoir(&mut stream);
            println!("[NETWORK] Received encrypted message ({} bytes)", message_recu.len());
            println!("[-] Received {} bytes", message_recu.len());

            //decripter
            println!("[DECRYPT]");
            println!("Cipher: {:02X?}", message_recu);
            let messagedecryte=decrypter(graineLGC,messagereçu);
            println!("Plain: {:?}\n", String::from_utf8_lossy(&message_decrypte));

            //crypter le message
            println!("[CHAT] Type message:");
            println!("[ENCRYPT]");
            let messagecrypte=encrypter(graineLGC);

            //envoyer message
            println!("[NETWORK] Sending encrypted message ({} bytes)...", message_crypte.len());
            envoyer(&mut stream, messagecrypter);
            println!("[-] Sent {} bytes\n", message_crypte.len());

        }
    }

    
}
