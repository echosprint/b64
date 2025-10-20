use base64::prelude::*;
use clap::Parser;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Encode a file to base64 txt file with simple encryption, or decode it
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// decode the base64 text file
    #[arg(short, long, action)]
    decode: bool,

    /// the file path to encode/decode
    #[arg(short, long, index = 1)]
    file: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    // println!("{:?}", args);
    let file_path = args.file;

    let path = Path::new(&file_path);

    let mut input_file = File::open(file_path.clone()).expect(&format!("{file_path} not found."));

    match args.decode {
        false => {
            let mut extention = path
                .extension()
                .map_or("", |v| v.to_str().unwrap())
                .to_string();
            if extention.len() > 0 {
                extention = format!(".{extention}");
            }
            let file_path_no_ext = file_path.trim_end_matches(&extention).to_string();

            let output_path = format!("{}.b64.txt", file_path_no_ext);

            encode_file(&mut input_file, &output_path, &extention)?
        }

        true => {
            if !file_path.ends_with(".b64.txt") {
                panic!("Only can decode file end with .b64.txt file");
            }
            let output_path = file_path.trim_end_matches(".b64.txt").to_string();
            decode_file(&mut input_file, &output_path)?
        }
    };

    Ok(())
}

fn encode_file(input_file: &mut File, output_path: &str, extention: &str) -> io::Result<()> {
    let mut buffer = Vec::new();

    let prefix_len: u8 = (extention.len() + 1) as u8;

    let ext_vec_u8: Vec<u8> = extention.as_bytes().to_vec();

    buffer.push(prefix_len);
    buffer.extend(ext_vec_u8);

    input_file.read_to_end(&mut buffer)?;

    let encrypt_buffer: Vec<u8> = buffer
        .iter()
        .map(|&x| ((x as u16 + 0xAA) % 256) as u8)
        .collect();
    let encoded = BASE64_STANDARD.encode(encrypt_buffer);

    let mut output_file = File::create(output_path)?;

    output_file.write_all(encoded.as_bytes())?;

    Ok(())
}

fn decode_file(input_file: &mut File, output_path: &str) -> io::Result<()> {
    let mut encoded_string = String::new();

    input_file.read_to_string(&mut encoded_string)?;

    let decoded_encrypt = BASE64_STANDARD
        .decode(encoded_string)
        .expect("Failed to decode Base64");

    let decoded: Vec<u8> = decoded_encrypt
        .iter()
        .map(|&x| ((x as u16 + 256 - 0xAA) % 256) as u8)
        .collect();

    let prefix_len = decoded[0] as usize;

    let extention = std::str::from_utf8(&decoded[1..prefix_len])
        .unwrap()
        .to_string();

    let mut output_file = File::create(format!("{output_path}{extention}"))?;

    output_file.write_all(&decoded[prefix_len..])?;
    Ok(())
}
