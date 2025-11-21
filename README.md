# b64 - Encrypted Base64 File Encoder

A high-performance file encoder that combines ChaCha20-Poly1305 authenticated encryption with base64 encoding. Available in both Rust and JavaScript implementations with cross-compatible file formats.

## Features

- 🔒 **ChaCha20-Poly1305 AEAD Encryption** - Authenticated encryption with tamper detection
- 🔑 **PBKDF2 Key Derivation** - Secure password-based key generation (100,000 iterations, SHA-256)
- 🔐 **Custom Password Support** - CLI flag (`-p`) and environment variable (`B64_ECRY_PASSWORD`)
- 📦 **File Extension Preservation** - Automatically restores original file extensions
- 🛡️ **Tamper Detection** - Authentication tag verification ensures file integrity
- 🔄 **Cross-Compatible** - Rust and JavaScript versions can encode/decode each other's files
- ⚡ **Streaming Support** - Handles large files (5GB+) without excessive memory usage

## Installation

### Rust Version

```bash
cargo build --release
```

The binary will be available at `./target/release/b64`

### JavaScript Version

```bash
# Requires Node.js 14+
chmod +x src/b64.mjs
```

## Usage

### Encoding a File

**Rust:**
```bash
./target/release/b64 <file>
```

**JavaScript:**
```bash
node src/b64.mjs <file>
```

**Example:**
```bash
./target/release/b64 document.pdf
# Creates: document.b64.txt
```

### Decoding a File

**Rust:**
```bash
./target/release/b64 -d <file.b64.txt>
```

**JavaScript:**
```bash
node src/b64.mjs -d <file.b64.txt>
```

**Example:**
```bash
./target/release/b64 -d document.b64.txt
# Restores: document.pdf
```

## Password Configuration

Both implementations support custom passwords for encryption/decryption. Passwords are concatenated with a built-in default password for additional security.

### Password Priority

1. **CLI Flag** (highest priority): `-p` or `--password`
2. **Environment Variable**: `B64_ECRY_PASSWORD`
3. **Default Only**: Built-in default password

### Using CLI Password

**Rust:**
```bash
# Encode with password
./target/release/b64 -p "mySecret" document.pdf

# Decode with password
./target/release/b64 -d -p "mySecret" document.b64.txt
```

**JavaScript:**
```bash
# Encode with password
node src/b64.mjs -p "mySecret" document.pdf

# Decode with password
node src/b64.mjs -d -p "mySecret" document.b64.txt
```

**Note:** Always use quotes around passwords containing spaces or special characters:
```bash
./target/release/b64 -p 'P@$$w0rd!#$%' file.txt
```

### Using Environment Variable

Set the `B64_ECRY_PASSWORD` environment variable to avoid typing the password repeatedly:

**Rust:**
```bash
# Set password for current session
export B64_ECRY_PASSWORD="mySecret"

# Encode multiple files without typing password
./target/release/b64 file1.pdf
./target/release/b64 file2.txt
./target/release/b64 -d file1.b64.txt
```

**JavaScript:**
```bash
# Set password for current session
export B64_ECRY_PASSWORD="mySecret"

# Encode/decode without typing password
node src/b64.mjs file1.pdf
node src/b64.mjs -d file1.b64.txt
```

**CLI flag overrides environment variable:**
```bash
export B64_ECRY_PASSWORD="envPassword"
./target/release/b64 -p "cliPassword" file.txt  # Uses "cliPassword"
```

### Cross-Implementation Compatibility

Files encrypted with the same password work across both implementations:

```bash
# Encode with Rust
./target/release/b64 -p "shared" document.pdf

# Decode with JavaScript
node src/b64.mjs -d -p "shared" document.b64.txt
```

Environment variables work identically:
```bash
export B64_ECRY_PASSWORD="shared"
./target/release/b64 file.txt
node src/b64.mjs -d file.b64.txt  # Works!
```

## File Format Specification

### Header Layout (96 bytes)

```
┌──────────────────────────────────────────────────────────────────────┐
│ Offset │ Size │ Field         │ Description                          │
├──────────────────────────────────────────────────────────────────────┤
│   0-1  │  2   │ Magic Number  │ 0xB6, 0x4F (file format identifier)  │
│   2    │  1   │ Version       │ 0x01 (format version)                │
│   3    │  1   │ Flags         │ Reserved for future flags            │
│   4    │  1   │ Cipher Type   │ 0x01 = ChaCha20-Poly1305             │
│   5-7  │  3   │ Reserved      │ Reserved for future use              │
├──────────────────────────────────────────────────────────────────────┤
│   8    │  1   │ Ext Length    │ Length of file extension (≤16)       │
│  9-16  │  8   │ File Size     │ Original file size (uint64 BE)       │
│ 17-32  │ 16   │ Extension     │ File extension (UTF-8, null padded)  │
├──────────────────────────────────────────────────────────────────────┤
│ 33-48  │ 16   │ Nonce         │ Random nonce (12 bytes used)         │
│ 49-64  │ 16   │ Salt          │ PBKDF2 salt for key derivation       │
│ 65-80  │ 16   │ Auth Tag      │ ChaCha20-Poly1305 authentication tag │
│ 81-95  │ 15   │ Reserved      │ Reserved for future use              │
└──────────────────────────────────────────────────────────────────────┘
```

### Encryption Flow

1. **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
2. **Encryption**: ChaCha20-Poly1305 with Additional Authenticated Data (AAD)
3. **AAD**: First 65 bytes + last 15 bytes of header (everything except auth tag)
4. **Output**: Base64-encoded (Header + Encrypted Data)

## Performance Comparison

Benchmarks performed on macOS with various file sizes:

### Encoding Performance

| File Size | Rust Time | Rust Throughput | JS Time | JS Throughput | **JS Advantage** |
|-----------|-----------|-----------------|---------|---------------|------------------|
| 100 MB    | 0.709s    | ~141 MB/s      | 0.185s  | ~541 MB/s    | **3.8x faster**  |
| 500 MB    | 3.266s    | ~153 MB/s      | 0.687s  | ~728 MB/s    | **4.8x faster**  |
| 1 GB      | ~7.0s     | ~146 MB/s      | ~1.4s   | ~735 MB/s    | **5.0x faster**  |
| 5 GB      | ~113s     | ~45 MB/s       | ~11.6s  | ~440 MB/s    | **10x faster**   |

### Architecture Differences

#### JavaScript Implementation (Faster for Large Files)
- ✅ **True Streaming**: Processes files in 192KB chunks via Node.js Transform streams
- ✅ **Incremental Encryption**: Uses `cipher.update()` for chunk-by-chunk processing
- ✅ **Memory Efficient**: Peak memory usage ~200KB regardless of file size
- ✅ **Native Bindings**: Leverages OpenSSL/BoringSSL via Node.js crypto module (C++)
- ✅ **Pipeline Architecture**: `ReadStream → Encrypt → Base64 → WriteStream`

```javascript
await pipeline(
    createReadStream(inputFilePath, { highWaterMark: CHUNK_SIZE }),
    encryptStream,                    // Processes chunks incrementally
    new Base64EncodeTransform(),
    createWriteStream(outputPath)
);
```

#### Rust Implementation (Current)
- ⚠️ **Memory-Based**: Loads entire file into memory before processing
- ⚠️ **Single-Pass AEAD**: Uses high-level ChaCha20Poly1305::encrypt() API
- ✅ **Pure Rust**: Zero C dependencies, fully auditable code
- ✅ **Type Safety**: Compile-time guarantees and memory safety
- ✅ **Buffered I/O**: Uses BufReader/BufWriter (256KB buffers)

```rust
let mut plaintext = Vec::new();
reader.read_to_end(&mut plaintext)?;  // Loads entire file
let ciphertext = cipher.encrypt(nonce, payload)?;
```

### Why JavaScript is Faster

1. **Streaming Architecture**: Node.js processes data incrementally without loading entire files
2. **OpenSSL Backend**: The crypto module uses highly optimized C code (same library as browsers)
3. **Chunk-by-Chunk Processing**: Transform streams allow incremental encryption
4. **Memory Efficiency**: Constant memory usage regardless of file size

### Rust Performance Notes

The current Rust implementation prioritizes:
- **Code Safety**: Pure Rust with no unsafe code
- **Correctness**: High-level AEAD API ensures proper authentication
- **Auditability**: No C dependencies, fully reviewable Rust code

**Potential Improvements:**
- Switch to streaming cipher API (ChaCha20 + Poly1305 separately)
- Use `ring` crate for streaming AEAD operations
- Use `openssl` crate bindings (same backend as JS, would match performance)

## Cross-Compatibility

Both implementations use the **identical binary format** and can encode/decode each other's files:

```bash
# Encode with Rust, decode with JavaScript
./target/release/b64 file.txt
node src/b64.mjs -d file.b64.txt

# Encode with JavaScript, decode with Rust
node src/b64.mjs file.txt
./target/release/b64 -d file.b64.txt
```

**Custom passwords work across implementations:**
```bash
# Encode with Rust using password
./target/release/b64 -p "secret" file.txt

# Decode with JavaScript using same password
node src/b64.mjs -d -p "secret" file.b64.txt
```

Both use the same:
- Password handling (CLI flags, environment variables, and default)
- PBKDF2 parameters (100,000 iterations, SHA-256)
- ChaCha20-Poly1305 AEAD configuration
- Header format (96 bytes)


### Encryption Details

- **Algorithm**: ChaCha20-Poly1305 (IETF RFC 8439)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (protects against brute-force)
- **Nonce**: 12 bytes (96 bits) - randomly generated per file
- **Salt**: 16 bytes (128 bits) - randomly generated per file
- **Auth Tag**: 16 bytes (128 bits) - prevents tampering

### Tamper Detection

Files are automatically validated on decoding:

```bash
$ ./target/release/b64 -d tampered.b64.txt
Authentication verification: FAILED
File may be corrupted or tampered with.
Error: Decryption failed
```

## Building from Source

### Rust

```bash
# Development build
cargo build

# Optimized release build
cargo build --release

# Run tests
cargo test
```

### Dependencies

**Rust (`Cargo.toml`):**
```toml
[dependencies]
base64 = "0.22.0"
clap = { version = "4.5.3", features = ["derive"] }
chacha20poly1305 = "0.10"
pbkdf2 = { version = "0.12", features = ["simple"] }
sha2 = "0.10"
rand = "0.8"
```

**JavaScript:**
- Node.js 14+ (built-in modules: `crypto`, `fs`, `stream`)

## Benchmarking

Run the included benchmark script:

```bash
# Quick benchmark (100MB + 500MB)
./quick_benchmark.sh

# Full benchmark (includes 1GB + optional 5GB)
python3 benchmark.py
```

## License

[Add your license here]

## Contributing

Contributions welcome! Areas of interest:
- [ ] Implement true streaming in Rust
- [x] ~~Add password CLI option~~ (Completed: `-p` flag and `B64_ECRY_PASSWORD` env var)
- [ ] Add compression support
- [ ] Multi-threaded encryption for large files
- [ ] Progress indicators
- [ ] Batch processing support

## Changelog

### v0.2.0 (Current)
- **Added**: Custom password support via `-p`/`--password` CLI flag
- **Added**: `B64_ECRY_PASSWORD` environment variable support
- **Added**: Password priority system (CLI > Environment > Default)
- **Updated**: Cross-implementation password compatibility
- Full backward compatibility with v0.1.0 (default password unchanged)

### v0.1.0
- Initial implementation
- ChaCha20-Poly1305 AEAD encryption
- PBKDF2 key derivation
- Cross-compatible Rust/JS versions
- File extension preservation
- Tamper detection
