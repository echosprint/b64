//! b64 - Base64 encoder/decoder with ChaCha20-Poly1305 encryption
//!
//! Encodes files to base64 with authenticated encryption and file extension preservation.
//! Features: ChaCha20-Poly1305 AEAD, PBKDF2 key derivation, tamper detection, file splitting
//!
//! Usage:
//!   Encode: b64 [-p <password>] [-s <size>] <file>
//!   Decode: b64 -d [-p <password>] <file.b64.txt>
//!
//! Split files (e.g., file_0301.b64.txt) are auto-detected and combined when decoding.

use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use clap::Parser;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

// Header format constants
const HEADER_SIZE: usize = 96;
const MAGIC_NUMBER: [u8; 2] = [0xB6, 0x4F];
const VERSION: u8 = 0x01;

// Cipher types
const CIPHER_CHACHA20_POLY1305: u8 = 0x01;

const MAX_EXTENSION_LENGTH: usize = 16;
const MIN_SPLIT_SIZE: usize = 1024; // 1KB minimum split size (header is 128 base64 chars)
const DEFAULT_PASSWORD: &str = "xK9$mP2vL#nQ8wR@jF5yT!hB7dC*sE4uA6zN&gH3iV%oW1eX0pU-qM+kJ/lY~rI|fD=tG?bZ^cS>aL<vN)wQ(hE}jK{mP]nR[oT";

// PBKDF2 iterations (matching JS version)
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Parsed split file name info
struct SplitFileInfo {
    base_path: String,
    total_files: u32,
    #[allow(dead_code)]
    file_index: u32,
}

/// Parse split file name pattern: baseName_XXYY.b64.txt
/// where XX = total files, YY = file index (01-99)
fn parse_split_file_name(file_path: &str) -> Option<SplitFileInfo> {
    // Must end with .b64.txt
    let without_ext = file_path.strip_suffix(".b64.txt")?;

    // Must have _XXYY pattern at end (4 digits)
    if without_ext.len() < 5 {
        return None;
    }

    let (base, digits) = without_ext.rsplit_once('_')?;

    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let total_files: u32 = digits[0..2].parse().ok()?;
    let file_index: u32 = digits[2..4].parse().ok()?;

    // Validate: index should be between 1 and total
    if file_index < 1 || file_index > total_files || total_files > 99 {
        return None;
    }

    Some(SplitFileInfo {
        base_path: base.to_string(),
        total_files,
        file_index,
    })
}

/// Get all split file paths for a given split file
fn get_split_file_paths(file_path: &str) -> io::Result<Option<Vec<String>>> {
    let info = match parse_split_file_name(file_path) {
        Some(info) => info,
        None => return Ok(None),
    };

    let mut paths = Vec::new();

    for i in 1..=info.total_files {
        let part_path = format!("{}_{:02}{:02}.b64.txt", info.base_path, info.total_files, i);
        if !Path::new(&part_path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Missing split file part: {}", part_path),
            ));
        }
        paths.push(part_path);
    }

    Ok(Some(paths))
}

/// Encode a file to base64 txt file with ChaCha20-Poly1305 encryption, or decode it
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Decode the base64 text file
    #[arg(short, long, action)]
    decode: bool,

    /// Password to use for encryption/decryption (concatenated with default password).
    /// If not provided, uses B64_ECRY_PASSWORD environment variable if set
    #[arg(short, long)]
    password: Option<String>,

    /// Maximum size per output file (e.g., 5mb, 500kb, 1gb). If output exceeds this,
    /// splits into multiple files named filename_XXYY.b64.txt (XX=total, YY=index)
    #[arg(short, long, value_parser = parse_size)]
    size: Option<usize>,

    /// The file path to encode/decode
    #[arg(index = 1)]
    file: String,
}

/// Parse size string to bytes (e.g., "5mb", "500kb", "1gb")
fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.to_lowercase();
    let (num_str, unit) = if s.ends_with("gb") {
        (&s[..s.len()-2], 1024 * 1024 * 1024)
    } else if s.ends_with("mb") {
        (&s[..s.len()-2], 1024 * 1024)
    } else if s.ends_with("kb") {
        (&s[..s.len()-2], 1024)
    } else if s.ends_with("b") {
        (&s[..s.len()-1], 1)
    } else {
        (s.as_str(), 1)
    };

    let size = num_str.trim().parse::<f64>()
        .map(|n| (n * unit as f64) as usize)
        .map_err(|_| format!("Invalid size format: {}. Use format like '5mb', '500kb', '1gb'", s))?;

    if size < MIN_SPLIT_SIZE {
        return Err(format!("--size must be at least {} bytes (1KB)", MIN_SPLIT_SIZE));
    }

    Ok(size)
}

/// Header field offsets for 96-byte binary layout
mod header_layout {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 2;
    pub const FLAGS: usize = 3;
    pub const CIPHER_TYPE: usize = 4;
    #[allow(dead_code)]
    pub const RESERVED_1: usize = 5; // Reserved for future use
    pub const EXT_LENGTH: usize = 8;
    pub const FILE_SIZE: usize = 9;
    pub const EXTENSION: usize = 17;
    pub const NONCE: usize = 33;
    pub const SALT: usize = 49;
    pub const AUTH_TAG: usize = 65;
    pub const RESERVED_2: usize = 81;
}

/**
 * Header structure for encoding/decoding 96-byte file headers
 *
 * Header Layout (96 bytes total):
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ Offset │ Size │ Field         │ Description                          │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │   0-1  │  2   │ Magic Number  │ 0xB6, 0x4F (file format identifier)  │
 * │   2    │  1   │ Version       │ 0x01 (format version)                │
 * │   3    │  1   │ Flags         │ Reserved for future flags            │
 * │   4    │  1   │ Cipher Type   │ 0x01 = ChaCha20-Poly1305             │
 * │   5-7  │  3   │ Reserved      │ Reserved for future use              │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │   8    │  1   │ Ext Length    │ Length of file extension (≤16)       │
 * │  9-16  │  8   │ File Size     │ Original file size (uint64 BE)       │
 * │ 17-32  │ 16   │ Extension     │ File extension (UTF-8, null padded)  │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │ 33-48  │ 16   │ Nonce         │ Random nonce (12 bytes used)         │
 * │ 49-64  │ 16   │ Salt          │ PBKDF2 salt for key derivation       │
 * │ 65-80  │ 16   │ Auth Tag      │ ChaCha20-Poly1305 authentication tag │
 * │ 81-95  │ 15   │ Reserved      │ Reserved for future use              │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 * AAD (Additional Authenticated Data):
 *   - Bytes 0-64 (all fields before authTag) + Bytes 81-95 (reserved after authTag)
 *   - Total 80 bytes authenticated but not encrypted
 *   - Protects header metadata from tampering
 */
#[derive(Debug)]
struct Header {
    extension: String,
    file_size: u64,
    cipher_type: u8,
    nonce: [u8; 16],
    salt: [u8; 16],
    auth_tag: [u8; 16],
}

impl Header {
    /// Create a new header with validation
    fn new(extension: String, file_size: u64, nonce: [u8; 16], salt: [u8; 16]) -> io::Result<Self> {
        if extension.len() > MAX_EXTENSION_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Extension too long: {} (max {} chars)",
                    extension, MAX_EXTENSION_LENGTH
                ),
            ));
        }
        Ok(Self {
            extension,
            file_size,
            cipher_type: CIPHER_CHACHA20_POLY1305,
            nonce,
            salt,
            auth_tag: [0u8; 16],
        })
    }

    /// Get Additional Authenticated Data (AAD) for AEAD encryption
    ///
    /// AAD includes all header fields except the authTag itself:
    ///   - Bytes 0-64: Everything before authTag (metadata, nonce, salt)
    ///   - Bytes 81-95: Reserved section after authTag
    ///
    /// Total: 80 bytes authenticated but not encrypted
    /// This protects header metadata from tampering
    fn get_aad(&self) -> Vec<u8> {
        let header_buffer: [u8; HEADER_SIZE] = self.into();
        let mut aad = Vec::with_capacity(80);
        aad.extend_from_slice(&header_buffer[..header_layout::AUTH_TAG]);
        aad.extend_from_slice(&header_buffer[header_layout::RESERVED_2..HEADER_SIZE]);
        aad
    }
}

/// Serialize Header to 96-byte buffer
impl From<&Header> for [u8; HEADER_SIZE] {
    fn from(header: &Header) -> Self {
        let mut buf = [0u8; HEADER_SIZE];

        // Magic + Version + Flags + Cipher + Reserved (8 bytes)
        buf[header_layout::MAGIC..header_layout::VERSION].copy_from_slice(&MAGIC_NUMBER);
        buf[header_layout::VERSION] = VERSION;
        buf[header_layout::FLAGS] = 0x00;
        buf[header_layout::CIPHER_TYPE] = header.cipher_type;

        // Extension length + File size (9 bytes)
        buf[header_layout::EXT_LENGTH] = header.extension.len() as u8;
        buf[header_layout::FILE_SIZE..header_layout::FILE_SIZE + 8]
            .copy_from_slice(&header.file_size.to_be_bytes());

        // Extension (16 bytes, UTF-8, null padded)
        let ext_bytes = header.extension.as_bytes();
        buf[header_layout::EXTENSION..header_layout::EXTENSION + ext_bytes.len()]
            .copy_from_slice(ext_bytes);

        // Nonce (16 bytes)
        buf[header_layout::NONCE..header_layout::SALT].copy_from_slice(&header.nonce);

        // Salt (16 bytes)
        buf[header_layout::SALT..header_layout::AUTH_TAG].copy_from_slice(&header.salt);

        // Auth Tag (16 bytes)
        buf[header_layout::AUTH_TAG..header_layout::RESERVED_2].copy_from_slice(&header.auth_tag);

        // Reserved (15 bytes) - already zeroed

        buf
    }
}

/// Deserialize Header from 96-byte buffer
impl TryFrom<&[u8]> for Header {
    type Error = io::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid header size: {} (expected {})",
                    buf.len(),
                    HEADER_SIZE
                ),
            ));
        }

        // Validate magic number
        if &buf[header_layout::MAGIC..header_layout::VERSION] != &MAGIC_NUMBER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid file format: magic number mismatch",
            ));
        }

        // Validate version
        let version = buf[header_layout::VERSION];
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported version: {}", version),
            ));
        }

        let cipher_type = buf[header_layout::CIPHER_TYPE];

        // Extension length + File size
        let ext_len = buf[header_layout::EXT_LENGTH] as usize;
        let file_size = u64::from_be_bytes(
            buf[header_layout::FILE_SIZE..header_layout::FILE_SIZE + 8]
                .try_into()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid file size field")
                })?,
        );

        // Extension (validate UTF-8)
        let extension = std::str::from_utf8(
            &buf[header_layout::EXTENSION..header_layout::EXTENSION + ext_len],
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid UTF-8 in extension: {}", e),
            )
        })?
        .to_string();

        // Nonce, Salt, Auth Tag (with proper error handling)
        let nonce = buf[header_layout::NONCE..header_layout::SALT]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid nonce field"))?;

        let salt = buf[header_layout::SALT..header_layout::AUTH_TAG]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid salt field"))?;

        let auth_tag = buf[header_layout::AUTH_TAG..header_layout::RESERVED_2]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid auth tag field"))?;

        Ok(Self {
            extension,
            file_size,
            cipher_type,
            nonce,
            salt,
            auth_tag,
        })
    }
}

/// Derive encryption key from password using PBKDF2
fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encode a file to base64 with ChaCha20-Poly1305 encryption
///
/// Process flow:
///   1. Get file size and generate nonce + salt
///   2. Encrypt file with ChaCha20-Poly1305
///   3. Get authentication tag
///   4. Create 96-byte header with metadata
///   5. Prepend header
///   6. Base64 encode
///   7. Write to .b64.txt file (or split files if max_size specified)
fn encode_file(input_path: &str, password: &str, max_size: Option<usize>) -> io::Result<()> {
    let path = Path::new(input_path);

    // Extract file extension
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s))
        .unwrap_or_default();

    if extension.len() > MAX_EXTENSION_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Extension too long: {} (max {} chars)",
                extension, MAX_EXTENSION_LENGTH
            ),
        ));
    }

    // Get file size
    let file_size = std::fs::metadata(input_path)?.len();

    // Early check: validate split won't exceed 99 files
    if let Some(max_size) = max_size {
        // Estimate base64 output size: ~4/3 of (header + encrypted data)
        let estimated_output_size = ((HEADER_SIZE as u64 + file_size) * 4 / 3) as usize;
        let estimated_files = (estimated_output_size + max_size - 1) / max_size;
        if estimated_files > 99 {
            let min_size = (estimated_output_size + 98) / 99; // ceil division
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Output would require ~{} files (max 99). Increase --size to at least {} bytes",
                    estimated_files, min_size
                ),
            ));
        }
    }

    // Generate random nonce and salt
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 16];
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut salt);

    // Derive key
    let key = derive_key(password, &salt);

    // Create header with placeholder auth tag
    let mut header = Header::new(extension.clone(), file_size, nonce, salt)?;

    // Get AAD from header
    let aad = header.get_aad();

    // Create cipher
    let cipher = ChaCha20Poly1305::new((&key).into());

    // Read and encrypt file
    let input_file = File::open(input_path)?;
    let mut reader = BufReader::new(input_file);

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    // Encrypt with AAD
    let nonce_12 = Nonce::from_slice(&nonce[0..12]);
    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let ciphertext = cipher.encrypt(nonce_12, payload).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e))
    })?;

    // Extract auth tag (last 16 bytes of ciphertext)
    let encrypted_data = &ciphertext[..ciphertext.len() - 16];
    let auth_tag: [u8; 16] = ciphertext[ciphertext.len() - 16..]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid auth tag"))?;

    // Update header with auth tag
    header.auth_tag = auth_tag;

    // Serialize header and create output buffer
    let header_bytes: [u8; HEADER_SIZE] = (&header).into();
    let mut output_buffer = Vec::with_capacity(HEADER_SIZE + encrypted_data.len());
    output_buffer.extend_from_slice(&header_bytes);
    output_buffer.extend_from_slice(encrypted_data);

    // Base64 encode
    let encoded = BASE64_STANDARD.encode(&output_buffer);

    // Base path for output files
    let base_path = input_path.trim_end_matches(&extension).to_string();

    // Handle splitting if max_size is specified
    if let Some(max_size) = max_size {
        let encoded_bytes = encoded.as_bytes();
        let total_files = (encoded_bytes.len() + max_size - 1) / max_size;

        // Note: Early check above ensures total_files <= 99
        let mut output_paths = Vec::new();

        for (i, chunk) in encoded_bytes.chunks(max_size).enumerate() {
            let file_num = i + 1;
            let output_path = format!("{}_{:02}{:02}.b64.txt", base_path, total_files, file_num);
            let output_file = File::create(&output_path)?;
            let mut writer = BufWriter::new(output_file);
            writer.write_all(chunk)?;
            output_paths.push(output_path);
        }

        println!("Encoded: {} -> {} files:", input_path, output_paths.len());
        for path in &output_paths {
            println!("  {}", path);
        }
    } else {
        // Single file output
        let output_path = base_path + ".b64.txt";
        let output_file = File::create(&output_path)?;
        let mut writer = BufWriter::new(output_file);
        writer.write_all(encoded.as_bytes())?;

        println!("Encoded: {} -> {}", input_path, output_path);
    }

    Ok(())
}

/// Decode a .b64.txt file back to its original format
/// Automatically detects and handles split files (filename_XXYY.b64.txt pattern)
///
/// Process flow:
///   1. Detect if input is a split file, gather all parts if so
///   2. Read .b64.txt file(s)
///   3. Base64 decode
///   4. Extract and validate 96-byte header
///   5. Decrypt with ChaCha20-Poly1305 using header info
///   6. Write to original filename with correct extension
///   7. Verify authentication tag (delete output if tampered)
fn decode_file(input_path: &str, password: &str) -> io::Result<()> {
    // Validate input file extension
    if !input_path.ends_with(".b64.txt") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Only can decode file end with .b64.txt file",
        ));
    }

    // Check if this is a split file and get all parts
    let split_file_paths = get_split_file_paths(input_path)?;
    let (encoded_string, output_base_path) = if let Some(paths) = &split_file_paths {
        // Split file detected - combine all parts
        println!("Detected split file with {} parts", paths.len());
        let mut combined = String::new();
        for path in paths {
            let input_file = File::open(path)?;
            let mut reader = BufReader::new(input_file);
            reader.read_to_string(&mut combined)?;
        }
        // Output path based on the base path (remove _XXYY.b64.txt suffix)
        let info = parse_split_file_name(input_path).unwrap();
        (combined, info.base_path)
    } else {
        // Single file
        let input_file = File::open(input_path)?;
        let mut reader = BufReader::new(input_file);
        let mut encoded_string = String::new();
        reader.read_to_string(&mut encoded_string)?;
        let output_base_path = input_path.trim_end_matches(".b64.txt").to_string();
        (encoded_string, output_base_path)
    };

    // Base64 decode
    let decoded = BASE64_STANDARD.decode(&encoded_string).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Base64 decode failed: {}", e))
    })?;

    // Parse header using TryFrom trait
    let header = Header::try_from(&decoded[..])?;

    // Extract encrypted data (after header)
    let encrypted_data = &decoded[HEADER_SIZE..];

    // Derive key
    let key = derive_key(password, &header.salt);

    // Get AAD
    let aad = header.get_aad();

    // Create cipher
    let cipher = ChaCha20Poly1305::new((&key).into());

    // Reconstruct ciphertext with auth tag
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(encrypted_data);
    ciphertext.extend_from_slice(&header.auth_tag);

    // Decrypt with AAD
    let nonce_12 = Nonce::from_slice(&header.nonce[0..12]);
    let payload = Payload {
        msg: &ciphertext,
        aad: &aad,
    };

    let plaintext = cipher.decrypt(nonce_12, payload).map_err(|e| {
        eprintln!("Authentication verification: FAILED");
        eprintln!("File may be corrupted or tampered with.");
        io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed: {}", e))
    })?;

    // Write to output file
    let output_path = output_base_path + &header.extension;
    let output_file = File::create(&output_path)?;
    let mut writer = BufWriter::new(output_file);
    writer.write_all(&plaintext)?;

    if let Some(paths) = split_file_paths {
        println!("Decoded: {} split files -> {}", paths.len(), output_path);
    } else {
        println!("Decoded: {} -> {}", input_path, output_path);
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    // Password priority: CLI flag > Environment variable > Default only
    let user_password = args.password.or_else(|| env::var("B64_ECRY_PASSWORD").ok());

    // Concatenate user password with default password if provided
    let final_password = match user_password {
        Some(pwd) => format!("{}{}", pwd, DEFAULT_PASSWORD),
        None => DEFAULT_PASSWORD.to_string(),
    };

    if args.decode {
        if args.size.is_some() {
            eprintln!("Error: --size option cannot be used when decoding");
            std::process::exit(1);
        }
        decode_file(&args.file, &final_password)?;
    } else {
        encode_file(&args.file, &final_password, args.size)?;
    }

    Ok(())
}
