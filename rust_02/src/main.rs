use clap::Parser;
use std::io;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::io::Read;

#[derive(Parser, Debug)]
#[command(
    name = "hextool",
    about = "Read and write binary files in hexadecimal"
)]
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
