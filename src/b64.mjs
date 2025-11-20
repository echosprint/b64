#!/usr/bin/env node

/**
 * b64 - Base64 encoder/decoder with ChaCha20-Poly1305 encryption
 *
 * Encodes files to base64 with authenticated encryption and file extension preservation.
 * Uses streaming to handle large files (5GB+) without loading into memory.
 * Features: ChaCha20-Poly1305 AEAD, PBKDF2 key derivation, tamper detection
 *
 * Usage:
 *   Encode: node b64.mjs <file>
 *   Decode: node b64.mjs -d <file.b64.txt>
 */

import { createReadStream, createWriteStream, statSync, openSync, writeSync, closeSync } from 'fs';
import { parse as parsePath } from 'path';
import { Transform, Readable } from 'stream';
import { pipeline } from 'stream/promises';
import { randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } from 'crypto';

// Header format constants
const HEADER_SIZE = 96;
const MAGIC_NUMBER = Buffer.from([0xB6, 0x4F]);
const VERSION = 0x01;

// Cipher types
const CIPHER_CHACHA20_POLY1305 = 0x01;

const MAX_EXTENSION_LENGTH = 16;
const CHUNK_SIZE = 3 * 64 * 1024; // 192KB - aligned for base64 (divisible by 3)
const DEFAULT_PASSWORD = 'xK9$mP2vL#nQ8wR@jF5yT!hB7dC*sE4uA6zN&gH3iV%oW1eX0pU-qM+kJ/lY~rI|fD=tG?bZ^cS>aL<vN)wQ(hE}jK{mP]nR[oT';

/**
 * Derive encryption key from password using PBKDF2
 */
const deriveKey = (password, salt) => pbkdf2Sync(password, salt, 100000, 32, 'sha256');

/**
 * Header class for encoding/decoding 96-byte file headers
 */
class Header {
    constructor(extension, fileSize, nonce, salt, authTag) {
        if (extension.length > MAX_EXTENSION_LENGTH) {
            throw new Error(`Extension too long: ${extension} (max ${MAX_EXTENSION_LENGTH} chars)`);
        }
        this.extension = extension;
        this.fileSize = fileSize;
        this.cipherType = CIPHER_CHACHA20_POLY1305;
        this.nonce = nonce;
        this.salt = salt;
        this.authTag = authTag;
    }

    toBuffer() {
        const buf = Buffer.alloc(HEADER_SIZE);
        let pos = 0;

        // Magic + Version + Flags + Cipher + Reserved (8 bytes)
        MAGIC_NUMBER.copy(buf, pos); pos += 2;
        buf[pos++] = VERSION;
        buf[pos++] = 0x00; // Flags
        buf[pos++] = this.cipherType;
        pos += 3; // Reserved

        // Extension length + File size (9 bytes)
        buf[pos++] = this.extension.length;
        const high = Math.floor(this.fileSize / 0x100000000);
        const low = this.fileSize >>> 0;
        buf.writeUInt32BE(high, pos); buf.writeUInt32BE(low, pos + 4); pos += 8;

        // Extension (16 bytes)
        buf.write(this.extension, pos, MAX_EXTENSION_LENGTH, 'utf8'); pos += MAX_EXTENSION_LENGTH;

        // Nonce + Salt + AuthTag (48 bytes)
        this.nonce?.copy(buf, pos, 0, 16); pos += 16;
        this.salt?.copy(buf, pos, 0, 16); pos += 16;
        this.authTag?.copy(buf, pos, 0, 16); pos += 16;

        // Reserved (16 bytes) - already zeroed by alloc
        return buf;
    }

    static parse(buf) {
        if (buf.length < HEADER_SIZE) {
            throw new Error(`Invalid header size: ${buf.length} (expected ${HEADER_SIZE})`);
        }

        let pos = 0;

        // Validate magic + version
        if (!buf.subarray(pos, pos + 2).equals(MAGIC_NUMBER)) {
            throw new Error('Invalid file format: magic number mismatch');
        }
        pos += 2;

        const version = buf[pos++];
        if (version !== VERSION) {
            throw new Error(`Unsupported version: ${version}`);
        }

        // Skip flags, get cipher, skip reserved
        pos++; // Flags
        const cipherType = buf[pos++];
        pos += 3; // Reserved

        // Extension + File size
        const extLen = buf[pos++];
        const high = buf.readUInt32BE(pos);
        const low = buf.readUInt32BE(pos + 4);
        const fileSize = high * 0x100000000 + low;
        pos += 8;

        const extension = buf.toString('utf8', pos, pos + extLen);
        pos += MAX_EXTENSION_LENGTH;

        // Nonce + Salt + AuthTag
        const nonce = buf.subarray(pos, pos + 16); pos += 16;
        const salt = buf.subarray(pos, pos + 16); pos += 16;
        const authTag = buf.subarray(pos, pos + 16);

        const header = new Header(extension, fileSize, nonce, salt, authTag);
        header.cipherType = cipherType;
        return header;
    }
}

/**
 * Parse command line arguments
 * Supports: -d/--decode flag and positional file argument
 * @returns {Object} { decode: boolean, filePath: string }
 */
const parseArgs = () => {
    const args = process.argv.slice(2);
    let decode = false;
    let filePath = null;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-d' || args[i] === '--decode') {
            decode = true;
        } else if (!args[i].startsWith('-')) {
            filePath = args[i]; // Positional argument
        }
    }

    if (!filePath) {
        console.error('Error: File path is required');
        console.log('Usage: node b64.mjs [-d|--decode] <file_path>');
        process.exit(1);
    }

    return { decode, filePath };
};

/**
 * Transform stream for ChaCha20-Poly1305 encryption
 * Encrypts data in streaming mode
 */
class EncryptTransform extends Transform {
    constructor(password, nonce, salt, aad, options) {
        super(options);

        // Derive key from password
        const key = deriveKey(password, salt);

        // Create cipher (ChaCha20-Poly1305 requires 12-byte nonce, we use first 12 bytes)
        this.cipher = createCipheriv('chacha20-poly1305', key, nonce.subarray(0, 12), {
            authTagLength: 16
        });

        // Set Additional Authenticated Data (header without authTag)
        if (aad) {
            this.cipher.setAAD(aad, { plaintextLength: 0 });
        }
    }

    _transform = (chunk, _encoding, callback) => {
        try {
            const encrypted = this.cipher.update(chunk);
            this.push(encrypted);
            callback();
        } catch (err) {
            callback(err);
        }
    };

    _flush = (callback) => {
        try {
            const final = this.cipher.final();
            if (final.length > 0) {
                this.push(final);
            }
            // Get authentication tag
            this.authTag = this.cipher.getAuthTag();
            callback();
        } catch (err) {
            callback(err);
        }
    };

    getAuthTag = () => this.authTag;
}

/**
 * Transform stream for ChaCha20-Poly1305 decryption
 * Decrypts data in streaming mode and verifies authentication tag
 */
class DecryptTransform extends Transform {
    constructor(password, nonce, salt, authTag, aad, options) {
        super(options);

        // Derive key from password
        const key = deriveKey(password, salt);

        // Create decipher (ChaCha20-Poly1305 requires 12-byte nonce)
        this.decipher = createDecipheriv('chacha20-poly1305', key, nonce.subarray(0, 12), {
            authTagLength: 16
        });

        // Set Additional Authenticated Data (header without authTag)
        if (aad) {
            this.decipher.setAAD(aad, { plaintextLength: 0 });
        }

        // Set authentication tag
        this.decipher.setAuthTag(authTag);
    }

    _transform = (chunk, _encoding, callback) => {
        try {
            const decrypted = this.decipher.update(chunk);
            this.push(decrypted);
            callback();
        } catch (err) {
            callback(err);
        }
    };

    _flush = (callback) => {
        try {
            const final = this.decipher.final();
            if (final.length > 0) {
                this.push(final);
            }
            console.log('Authentication verification: PASSED');
            callback();
        } catch (err) {
            console.error('Authentication verification: FAILED');
            console.error('File may be corrupted or tampered with.');
            callback(err);
        }
    };
}

/**
 * Transform stream that prepends header before encrypted data
 */
class PrependHeaderTransform extends Transform {
    constructor(headerBuffer, options) {
        super(options);
        this.headerBuffer = headerBuffer;
        this.headerSent = false;
    }

    _transform = (chunk, _encoding, callback) => {
        if (!this.headerSent) {
            this.push(this.headerBuffer);
            this.headerSent = true;
        }
        this.push(chunk);
        callback();
    };
}

/**
 * Transform stream to encode binary data to base64
 * Processes data in chunks, handling 3-byte boundaries for proper base64 encoding
 * Stores leftover bytes that don't fit into 3-byte groups
 */
class Base64EncodeTransform extends Transform {
    leftover = Buffer.alloc(0); // Bytes from previous chunk that didn't fit in a 3-byte group

    _transform = (chunk, _encoding, callback) => {
        // Combine leftover from previous chunk with current chunk
        const data = Buffer.concat([this.leftover, chunk]);

        // Process in multiples of 3 bytes (base64 encodes 3 bytes to 4 characters)
        const processLength = Math.floor(data.length / 3) * 3;

        if (processLength > 0) {
            const toEncode = data.subarray(0, processLength);
            this.push(toEncode.toString('base64'));
        }

        // Save remaining bytes for next chunk
        this.leftover = data.subarray(processLength);
        callback();
    };

    _flush = (callback) => {
        // Encode any remaining bytes when stream ends
        if (this.leftover.length > 0) {
            this.push(this.leftover.toString('base64'));
        }
        callback();
    };
}

/**
 * Transform stream to decode base64 to binary data
 * Processes data in chunks, handling 4-character boundaries for proper base64 decoding
 * Stores leftover characters that don't fit into 4-character groups
 */
class Base64DecodeTransform extends Transform {
    leftover = ''; // Characters from previous chunk that didn't fit in a 4-char group

    _transform = (chunk, _encoding, callback) => {
        // Combine leftover from previous chunk with current chunk
        const data = this.leftover + chunk.toString();

        // Process in multiples of 4 characters (base64 decodes 4 characters to 3 bytes)
        const processLength = Math.floor(data.length / 4) * 4;

        if (processLength > 0) {
            const toDecode = data.slice(0, processLength);
            this.push(Buffer.from(toDecode, 'base64'));
        }

        // Save remaining characters for next chunk
        this.leftover = data.slice(processLength);
        callback();
    };

    _flush = (callback) => {
        // Decode any remaining characters when stream ends
        if (this.leftover.length > 0) {
            this.push(Buffer.from(this.leftover, 'base64'));
        }
        callback();
    };
}

/**
 * Transform stream to extract and skip the 96-byte header during decoding
 *
 * Header format (96 bytes):
 *   - Magic number, version, flags
 *   - Cipher type, nonce, salt, auth tag
 *   - File size, extension
 *
 * This stream extracts the header metadata and passes through only the encrypted file content
 */
class HeaderSkipTransform extends Transform {
    headerProcessed = false;  // Whether we've extracted the header yet
    header = null;            // Parsed header object
    buffer = Buffer.alloc(0); // Accumulate data until we can read the full header

    _transform = (chunk, _encoding, callback) => {
        if (!this.headerProcessed) {
            // Accumulate chunks until we have the full 96-byte header
            this.buffer = Buffer.concat([this.buffer, chunk]);

            if (this.buffer.length >= HEADER_SIZE) {
                try {
                    // Parse the header
                    this.header = Header.parse(this.buffer.subarray(0, HEADER_SIZE));

                    // Push the encrypted file content (after the header)
                    const content = this.buffer.subarray(HEADER_SIZE);
                    if (content.length > 0) {
                        this.push(content);
                    }

                    this.headerProcessed = true;
                    this.buffer = null; // Free memory
                    callback();
                    return;
                } catch (err) {
                    callback(err);
                    return;
                }
            }
            // Not enough data yet, wait for more chunks
            callback();
        } else {
            // Header already extracted, pass through remaining encrypted data
            this.push(chunk);
            callback();
        }
    };

    getExtension = () => this.header?.extension;
    getHeader = () => this.header;
}


/**
 * Encode a file to base64 with ChaCha20-Poly1305 encryption
 *
 * Process flow:
 *   1. Get file size and generate nonce + salt
 *   2. Encrypt file with ChaCha20-Poly1305
 *   3. Get authentication tag
 *   4. Create 96-byte header with metadata
 *   5. Prepend header
 *   6. Base64 encode
 *   7. Write to .b64.txt file
 *
 * @param {string} inputFilePath - Path to file to encode
 * @param {string} password - Encryption password (uses default if not provided)
 */
const encodeFile = async (inputFilePath, password = DEFAULT_PASSWORD) => {
    // Extract file extension
    const { ext: extension } = parsePath(inputFilePath);

    if (extension.length > MAX_EXTENSION_LENGTH) {
        throw new Error(`Extension too long: ${extension} (max ${MAX_EXTENSION_LENGTH} chars)`);
    }

    // Get file size
    const stats = statSync(inputFilePath);
    const fileSize = stats.size;

    // Generate random nonce and salt
    const nonce = randomBytes(16); // We'll use first 12 bytes for ChaCha20-Poly1305
    const salt = randomBytes(16);

    console.log('Encrypting with ChaCha20-Poly1305...');

    const outputPath = inputFilePath.replace(extension, '') + '.b64.txt';

    // Create header with placeholder authTag (all zeros)
    const placeholderHeader = new Header(extension, fileSize, nonce, salt, Buffer.alloc(16));
    const headerBuffer = placeholderHeader.toBuffer();

    // Header without authTag (first 64 bytes + last 16 bytes) to use as AAD
    const aad = Buffer.alloc(80);
    headerBuffer.copy(aad, 0, 0, 64);   // First 64 bytes (everything before authTag)
    headerBuffer.copy(aad, 64, 80, 96); // Last 16 bytes (reserved section after authTag)

    const encryptStream = new EncryptTransform(password, nonce, salt, aad);

    try {
        // Stream: file → encrypt (with AAD) → prepend header → base64 → output
        await pipeline(
            createReadStream(inputFilePath, { highWaterMark: CHUNK_SIZE }),
            encryptStream,
            new PrependHeaderTransform(headerBuffer),
            new Base64EncodeTransform(),
            createWriteStream(outputPath)
        );

        // Get authTag after encryption completes
        const authTag = encryptStream.getAuthTag();

        // Update authTag in the base64 file
        // AuthTag is at bytes 64-79 in header (16 bytes)
        // Base64 encodes in groups of 3 bytes → 4 chars
        // Bytes 63-80 (18 bytes) → chars 84-107 (24 chars)

        // Create the 18-byte chunk with real authTag
        const updatedChunk = Buffer.alloc(18);
        headerBuffer.copy(updatedChunk, 0, 63, 64);  // byte 63 (from placeholder header)
        authTag.copy(updatedChunk, 1, 0, 16);         // bytes 64-79 (real authTag)
        headerBuffer.copy(updatedChunk, 17, 80, 81); // byte 80 (from placeholder header)

        // Base64 encode this chunk
        const encodedChunk = updatedChunk.toString('base64');

        // Replace at position 84 in the output file
        const fd = openSync(outputPath, 'r+');
        const written = writeSync(fd, encodedChunk, 84, 'utf8');
        closeSync(fd);

        console.log(`Updated authTag at position 84 (${written} bytes written)`);

        console.log(`Encoded: ${inputFilePath} -> ${outputPath}`);
        console.log(`  Size: ${fileSize} bytes`);
        console.log(`  Cipher: ChaCha20-Poly1305`);
    } catch (err) {
        console.error(`Error during encoding: ${err.message}`);
        process.exit(1);
    }
};

/**
 * Decode a .b64.txt file back to its original format
 *
 * Process flow:
 *   1. Read .b64.txt file in 192KB chunks (streaming)
 *   2. Base64 decode
 *   3. Extract and validate 96-byte header
 *   4. Decrypt with ChaCha20-Poly1305 using header info
 *   5. Verify authentication tag
 *   6. Write to original filename with correct extension
 *
 * @param {string} inputFilePath - Path to .b64.txt file to decode
 * @param {string} password - Decryption password (uses default if not provided)
 */
const decodeFile = async (inputFilePath, password = DEFAULT_PASSWORD) => {
    // Validate input file extension
    if (!inputFilePath.endsWith('.b64.txt')) {
        throw new Error('Only can decode file end with .b64.txt file');
    }

    // Decode and extract header
    const headerSkipStream = new HeaderSkipTransform();
    const encryptedChunks = [];

    headerSkipStream.on('data', (chunk) => encryptedChunks.push(chunk));

    await pipeline(
        createReadStream(inputFilePath, { encoding: 'utf8', highWaterMark: CHUNK_SIZE }),
        new Base64DecodeTransform(),
        headerSkipStream
    );

    const header = headerSkipStream.getHeader();

    if (!header) {
        throw new Error('Failed to extract header');
    }

    console.log('Decrypting with ChaCha20-Poly1305...');

    // Create AAD from header (without authTag)
    const headerBuffer = header.toBuffer();
    const aad = Buffer.alloc(80);
    headerBuffer.copy(aad, 0, 0, 64);   // First 64 bytes (everything before authTag)
    headerBuffer.copy(aad, 64, 80, 96); // Last 16 bytes (reserved section after authTag)

    // Create decrypt stream with header info and AAD
    const encryptedData = Buffer.concat(encryptedChunks);
    const decryptStream = new DecryptTransform(password, header.nonce, header.salt, header.authTag, aad);

    // Decrypt and write to file
    const outputPath = inputFilePath.replace('.b64.txt', '') + header.extension;
    const outputStream = createWriteStream(outputPath);

    try {
        await pipeline(
            Readable.from([encryptedData]),
            decryptStream,
            outputStream
        );

        console.log(`Decoded: ${inputFilePath} -> ${outputPath}`);
        console.log(`  Size: ${header.fileSize} bytes`);
        console.log(`  Cipher: ChaCha20-Poly1305`);
    } catch (err) {
        console.error(`Error during decoding: ${err.message}`);
        process.exit(1);
    }
};

/**
 * Main entry point
 * Parses CLI arguments and routes to encode or decode function
 */
const main = async () => {
    try {
        const { decode, filePath } = parseArgs();

        if (decode) {
            await decodeFile(filePath);
        } else {
            await encodeFile(filePath);
        }
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

// Run the program
main();
