#!/usr/bin/env node

/**
 * b64 - Base64 encoder/decoder with ChaCha20-Poly1305 encryption
 *
 * Encodes files to base64 with authenticated encryption and file extension preservation.
 * Uses streaming to handle large files (5GB+) without loading into memory.
 * Features: ChaCha20-Poly1305 AEAD, PBKDF2 key derivation, tamper detection, file splitting
 *
 * Usage:
 *   Encode: node b64.mjs [-p <password>] [-s <size>] <file>
 *   Decode: node b64.mjs -d [-p <password>] <file.b64.txt>
 *
 * Split files (e.g., file_s03p01.b64.txt) are auto-detected and combined when decoding.
 */

import { createReadStream, createWriteStream, statSync, openSync, writeSync, closeSync, unlinkSync, existsSync, renameSync, readdirSync } from 'fs';
import { parse as parsePath, dirname, basename } from 'path';
import { Transform, Readable, PassThrough } from 'stream';
import { pipeline } from 'stream/promises';
import { randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } from 'crypto';

// Header format constants
const HEADER_SIZE = 96;
const MAGIC_NUMBER = Buffer.from([0xB6, 0x4F]);
const VERSION = 0x01;

// Cipher types
const CIPHER_CHACHA20_POLY1305 = 0x01;
const CIPHER_ALGORITHM = 'chacha20-poly1305';

const MAX_EXTENSION_LENGTH = 16;
const CHUNK_SIZE = 3 * 64 * 1024; // 192KB - aligned for base64 (divisible by 3)
const MIN_SPLIT_SIZE = 1024; // 1KB minimum split size (header is 128 base64 chars)
const DEFAULT_PASSWORD = 'xK9$mP2vL#nQ8wR@jF5yT!hB7dC*sE4uA6zN&gH3iV%oW1eX0pU-qM+kJ/lY~rI|fD=tG?bZ^cS>aL<vN)wQ(hE}jK{mP]nR[oT';

/**
 * Parse size string to bytes (e.g., "5mb", "500kb", "1gb")
 * Case insensitive, supports: b, kb, mb, gb
 * @param {string} sizeStr - Size string like "5mb" or "500KB"
 * @returns {number} Size in bytes
 */
const parseSize = (sizeStr) => {
    const match = sizeStr.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/);
    if (!match) {
        throw new Error(`Invalid size format: ${sizeStr}. Use format like "5mb", "500kb", "1gb"`);
    }
    const value = parseFloat(match[1]);
    const unit = match[2] || 'b';
    const multipliers = { b: 1, kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 };
    return Math.floor(value * multipliers[unit]);
};

/**
 * Parse split file name pattern: baseName_sXXpYY.b64.txt
 * where s = split marker, XX = total files, p = part marker, YY = file index (01-99)
 * @param {string} filePath - Path to check
 * @returns {Object|null} { basePath, totalFiles, fileIndex } or null if not a split file
 */
const parseSplitFileName = (filePath) => {
    const match = filePath.match(/^(.+)_s(\d{2})p(\d{2})\.b64\.txt$/);
    if (!match) return null;

    const [, basePath, totalStr, indexStr] = match;
    const totalFiles = parseInt(totalStr, 10);
    const fileIndex = parseInt(indexStr, 10);

    // Validate: index should be between 1 and total
    if (fileIndex < 1 || fileIndex > totalFiles || totalFiles > 99) {
        return null;
    }

    return { basePath, totalFiles, fileIndex };
};

/**
 * Get all split file paths for a given split file
 * @param {string} filePath - Path to any file in the split set
 * @returns {string[]|null} Array of all split file paths in order, or null if not a split file
 */
const getSplitFilePaths = (filePath) => {
    const parsed = parseSplitFileName(filePath);
    if (!parsed) return null;

    const { basePath, totalFiles } = parsed;
    const paths = [];

    for (let i = 1; i <= totalFiles; i++) {
        const partPath = `${basePath}_s${String(totalFiles).padStart(2, '0')}p${String(i).padStart(2, '0')}.b64.txt`;
        if (!existsSync(partPath)) {
            throw new Error(`Missing split file part: ${partPath}`);
        }
        paths.push(partPath);
    }

    return paths;
};

/**
 * Readable stream that combines multiple files into a single stream
 * Reads files sequentially and outputs their combined content
 */
class CombineSplitFilesReadable extends Readable {
    constructor(filePaths, options = {}) {
        super(options);
        this.filePaths = filePaths;
        this.currentIndex = 0;
        this.currentStream = null;
        this.isPaused = false;
    }

    _read() {
        // If we have a paused stream, resume it
        if (this.currentStream && this.isPaused) {
            this.isPaused = false;
            this.currentStream.resume();
            return;
        }

        // If we have an active stream, let it push data
        if (this.currentStream) return;

        // If no more files, signal end
        if (this.currentIndex >= this.filePaths.length) {
            this.push(null);
            return;
        }

        // Open next file
        const filePath = this.filePaths[this.currentIndex];
        this.currentStream = createReadStream(filePath, { encoding: 'utf8', highWaterMark: CHUNK_SIZE });

        this.currentStream.on('data', (chunk) => {
            // Pause the file stream if buffer is full
            if (!this.push(chunk)) {
                this.isPaused = true;
                this.currentStream.pause();
            }
        });

        this.currentStream.on('end', () => {
            this.currentStream = null;
            this.isPaused = false;
            this.currentIndex++;
            // Continue reading from next file
            this._read();
        });

        this.currentStream.on('error', (err) => {
            this.destroy(err);
        });
    }

    _destroy(err, callback) {
        if (this.currentStream) {
            this.currentStream.destroy();
            this.currentStream = null;
        }
        callback(err);
    }
}

/**
 * Derive encryption key from password using PBKDF2
 */
const deriveKey = (password, salt) => pbkdf2Sync(password, salt, 100000, 32, 'sha256');

/**
 * Header class for encoding/decoding 96-byte file headers
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

        // Reserved (15 bytes, pos=81-95) - already zeroed by alloc
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

    /**
     * Get Additional Authenticated Data (AAD) for AEAD encryption
     *
     * AAD includes all header fields except the authTag itself:
     *   - Bytes 0-64: Everything before authTag (metadata, nonce, salt)
     *   - Bytes 81-95: Reserved section after authTag
     *
     * Total: 80 bytes authenticated but not encrypted
     * This protects header metadata from tampering
     *
     * @returns {Buffer} 80-byte AAD buffer
     */
    getAAD() {
        const headerBuffer = this.toBuffer();
        const aad = Buffer.alloc(80);
        headerBuffer.copy(aad, 0, 0, 65);   // First 65 bytes (everything before authTag at pos 65)
        headerBuffer.copy(aad, 65, 81, 96); // Last 15 bytes (reserved section after authTag)
        return aad;
    }
}

/**
 * Print usage information and exit
 * @param {string|null} error - Error message to display (null for help)
 */
const printUsage = (error = null) => {
    if (error) {
        console.error(`Error: ${error}`);
    }
    console.log('Usage:');
    console.log('  Encode: node b64.mjs [-p|--password <password>] [-s|--size <size>] <file_path>');
    console.log('  Decode: node b64.mjs -d [-p|--password <password>] <file_path>');
    console.log('Options:');
    console.log('  -d, --decode              Decode a .b64.txt file');
    console.log('  -p, --password <password> Custom password (or set B64_ECRY_PASSWORD env var)');
    console.log('  -s, --size <size>         Max output file size, e.g., 5mb, 500kb (encode only)');
    console.log('Note:');
    console.log('  Split files (e.g., file_s03p01.b64.txt) are auto-detected when decoding.');
    process.exit(error ? 1 : 0);
};

/**
 * Parse command line arguments
 * Supports: -d/--decode flag, -p/--password option, -s/--size option, and positional file argument
 * @returns {Object} { decode: boolean, filePath: string, password: string|null, maxSize: number|null }
 */
const parseArgs = () => {
    const args = process.argv.slice(2);
    let decode = false;
    let filePath = null;
    let password = null;
    let maxSize = null;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-d' || args[i] === '--decode') {
            decode = true;
        } else if (args[i] === '-p' || args[i] === '--password') {
            // Get password from next argument
            if (i + 1 < args.length) {
                password = args[i + 1];
                i++; // Skip next argument since we consumed it
            } else {
                printUsage('--password requires a value');
            }
        } else if (args[i] === '-s' || args[i] === '--size') {
            // Get size from next argument
            if (i + 1 < args.length) {
                try {
                    maxSize = parseSize(args[i + 1]);
                    if (maxSize < MIN_SPLIT_SIZE) {
                        printUsage(`--size must be at least ${MIN_SPLIT_SIZE} bytes (1KB)`);
                    }
                    i++; // Skip next argument since we consumed it
                } catch (err) {
                    printUsage(err.message);
                }
            } else {
                printUsage('--size requires a value');
            }
        } else if (!args[i].startsWith('-')) {
            filePath = args[i]; // Positional argument
        }
    }

    if (!filePath) {
        printUsage('File path is required');
    }

    return { decode, filePath, password, maxSize };
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
        this.cipher = createCipheriv(CIPHER_ALGORITHM, key, nonce.subarray(0, 12), {
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
        this.decipher = createDecipheriv(CIPHER_ALGORITHM, key, nonce.subarray(0, 12), {
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
 * Writable stream that splits output into multiple files when size exceeds limit
 * File naming: basePath_XXYY.ext where XX=total files, YY=file number (01-99)
 */
class SplitWriteStream extends Transform {
    constructor(basePath, extension, maxSize, options) {
        super(options);
        this.basePath = basePath;
        this.extension = extension;
        this.maxSize = maxSize;
        this.currentSize = 0;
        this.fileIndex = 1;
        this.files = [];
        this.currentFd = null;
        this.buffer = Buffer.alloc(0);
        this._openNextFile();
    }

    _openNextFile() {
        if (this.currentFd !== null) {
            closeSync(this.currentFd);
        }
        // Temporary filename, will be renamed at the end
        const tempPath = `${this.basePath}_temp_${String(this.fileIndex).padStart(2, '0')}${this.extension}`;
        this.currentFd = openSync(tempPath, 'w');
        this.files.push(tempPath);
        this.currentSize = 0;
    }

    _transform(chunk, _encoding, callback) {
        try {
            let data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);

            while (data.length > 0) {
                const remaining = this.maxSize - this.currentSize;

                if (data.length <= remaining) {
                    // Fits in current file
                    writeSync(this.currentFd, data);
                    this.currentSize += data.length;
                    data = Buffer.alloc(0);
                } else {
                    // Need to split
                    const toWrite = data.subarray(0, remaining);
                    writeSync(this.currentFd, toWrite);
                    this.currentSize += toWrite.length;
                    data = data.subarray(remaining);

                    // Open next file
                    this.fileIndex++;
                    this._openNextFile();
                }
            }
            callback();
        } catch (err) {
            callback(err);
        }
    }

    _flush(callback) {
        try {
            if (this.currentFd !== null) {
                closeSync(this.currentFd);
                this.currentFd = null;
            }

            // Rename files with correct total count
            const totalFiles = this.files.length;
            const totalStr = String(totalFiles).padStart(2, '0');

            this.finalPaths = [];
            for (let i = 0; i < this.files.length; i++) {
                const indexStr = String(i + 1).padStart(2, '0');
                const finalPath = `${this.basePath}_s${totalStr}p${indexStr}${this.extension}`;
                renameSync(this.files[i], finalPath);
                this.finalPaths.push(finalPath);
            }

            callback();
        } catch (err) {
            callback(err);
        }
    }

    getFinalPaths() {
        return this.finalPaths || [];
    }
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
 * Combined transform stream for header extraction + decryption
 * Extracts header, then decrypts all subsequent data in streaming mode
 */
class HeaderAndDecryptTransform extends Transform {
    constructor(password, options) {
        super(options);
        this.password = password;
        this.headerProcessed = false;
        this.header = null;
        this.decipher = null;
        this.buffer = Buffer.alloc(0);
    }

    _transform = (chunk, _encoding, callback) => {
        if (!this.headerProcessed) {
            // Accumulate until we have the full header
            this.buffer = Buffer.concat([this.buffer, chunk]);

            if (this.buffer.length >= HEADER_SIZE) {
                try {
                    // Parse header
                    this.header = Header.parse(this.buffer.subarray(0, HEADER_SIZE));

                    // console.log('Decrypting with ChaCha20-Poly1305...');

                    // Get AAD from header (all fields except authTag)
                    const aad = this.header.getAAD();

                    // Derive key and create decipher
                    const key = deriveKey(this.password, this.header.salt);
                    this.decipher = createDecipheriv(CIPHER_ALGORITHM, key, this.header.nonce.subarray(0, 12), {
                        authTagLength: 16
                    });
                    this.decipher.setAAD(aad, { plaintextLength: 0 });
                    this.decipher.setAuthTag(this.header.authTag);

                    // Process encrypted content after header
                    const encryptedContent = this.buffer.subarray(HEADER_SIZE);
                    this.headerProcessed = true;
                    this.buffer = null; // Free memory

                    if (encryptedContent.length > 0) {
                        const decrypted = this.decipher.update(encryptedContent);
                        if (decrypted.length > 0) {
                            this.push(decrypted);
                        }
                    }

                    callback();
                    return;
                } catch (err) {
                    callback(err);
                    return;
                }
            }
            callback();
        } else {
            // Decrypt streaming data
            try {
                const decrypted = this.decipher.update(chunk);
                if (decrypted.length > 0) {
                    this.push(decrypted);
                }
                callback();
            } catch (err) {
                callback(err);
            }
        }
    };

    _flush = (callback) => {
        if (this.decipher) {
            try {
                const final = this.decipher.final();
                if (final.length > 0) {
                    this.push(final);
                }
                // console.log('Authentication verification: PASSED');
                callback();
            } catch (err) {
                console.error('Authentication verification: FAILED');
                console.error('File may be corrupted or tampered with.');
                callback(err);
            }
        } else {
            callback();
        }
    };

    getHeader = () => this.header;
    getExtension = () => this.header?.extension;
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
 *   7. Write to .b64.txt file (or split files if maxSize specified)
 *
 * @param {string} inputFilePath - Path to file to encode
 * @param {string} password - Encryption password (uses default if not provided)
 * @param {number|null} maxSize - Maximum size per output file in bytes (null = no splitting)
 */
const encodeFile = async (inputFilePath, password = DEFAULT_PASSWORD, maxSize = null) => {
    // Extract file extension
    const { ext: extension } = parsePath(inputFilePath);

    if (extension.length > MAX_EXTENSION_LENGTH) {
        throw new Error(`Extension too long: ${extension} (max ${MAX_EXTENSION_LENGTH} chars)`);
    }

    // Get file size
    const stats = statSync(inputFilePath);
    const fileSize = stats.size;

    // Early check: validate split won't exceed 99 files
    if (maxSize) {
        // Estimate base64 output size: ~4/3 of (header + encrypted data)
        const estimatedOutputSize = Math.ceil((HEADER_SIZE + fileSize) * 4 / 3);
        const estimatedFiles = Math.ceil(estimatedOutputSize / maxSize);
        if (estimatedFiles > 99) {
            throw new Error(
                `Output would require ~${estimatedFiles} files (max 99). ` +
                `Increase --size to at least ${Math.ceil(estimatedOutputSize / 99)} bytes`
            );
        }
    }

    // Generate random nonce and salt
    const nonce = randomBytes(16); // We'll use first 12 bytes for ChaCha20-Poly1305
    const salt = randomBytes(16);

    // console.log('Encrypting with ChaCha20-Poly1305...');

    const basePath = inputFilePath.replace(extension, '');
    const outputPath = basePath + '.b64.txt';

    // Create header with placeholder authTag (all zeros)
    const placeholderHeader = new Header(extension, fileSize, nonce, salt, Buffer.alloc(16));
    const headerBuffer = placeholderHeader.toBuffer();

    // Get AAD from header (all fields except authTag)
    const aad = placeholderHeader.getAAD();

    const encryptStream = new EncryptTransform(password, nonce, salt, aad);

    try {
        let splitStream = null;
        let outputStream;

        if (maxSize) {
            // Use split write stream for size-limited output
            splitStream = new SplitWriteStream(basePath, '.b64.txt', maxSize);
            outputStream = splitStream;
        } else {
            // Normal single file output
            outputStream = createWriteStream(outputPath);
        }

        // Stream: file → encrypt (with AAD) → prepend header → base64 → output
        await pipeline(
            createReadStream(inputFilePath, { highWaterMark: CHUNK_SIZE }),
            encryptStream,
            new PrependHeaderTransform(headerBuffer),
            new Base64EncodeTransform(),
            outputStream
        );

        // Get authTag after encryption completes
        const authTag = encryptStream.getAuthTag();

        // Update authTag in the header buffer
        // AuthTag is at bytes 65-80 in header (16 bytes)
        authTag.copy(headerBuffer, 65, 0, 16);

        // Base64 encode the entire updated header (96 bytes → 128 base64 chars)
        const encodedHeader = headerBuffer.toString('base64');

        if (splitStream) {
            // Update header in the first split file
            const finalPaths = splitStream.getFinalPaths();
            if (finalPaths.length > 0) {
                const fd = openSync(finalPaths[0], 'r+');
                writeSync(fd, encodedHeader, 0, 'utf8');
                closeSync(fd);
            }

            console.log(`Encoded: ${inputFilePath} -> ${finalPaths.length} files:`);
            for (const path of finalPaths) {
                console.log(`  ${path}`);
            }
        } else {
            // Replace the header in the single output file
            const fd = openSync(outputPath, 'r+');
            writeSync(fd, encodedHeader, 0, 'utf8');
            closeSync(fd);

            console.log(`Encoded: ${inputFilePath} -> ${outputPath}`);
        }
        // console.log(`  Size: ${fileSize} bytes`);
        // console.log(`  Cipher: ChaCha20-Poly1305`);
    } catch (err) {
        console.error(`Error during encoding: ${err.message}`);
        process.exit(1);
    }
};

/**
 * Decode a .b64.txt file back to its original format
 * Automatically detects and handles split files (filename_XXYY.b64.txt pattern)
 *
 * Process flow (single streaming pipeline):
 *   1. Detect if input is a split file, gather all parts if so
 *   2. Read file(s) in 192KB chunks (streaming)
 *   3. Base64 decode
 *   4. Extract and validate 96-byte header
 *   5. Decrypt with ChaCha20-Poly1305 using header info
 *   6. Write to original filename with correct extension
 *   7. Verify authentication tag at end (delete output if tampered)
 *
 * @param {string} inputFilePath - Path to .b64.txt file to decode
 * @param {string} password - Decryption password (uses default if not provided)
 */
const decodeFile = async (inputFilePath, password = DEFAULT_PASSWORD) => {
    // Validate input file extension
    if (!inputFilePath.endsWith('.b64.txt')) {
        throw new Error('Only can decode file end with .b64.txt file');
    }

    // Check if this is a split file and get all parts
    let inputStream;
    let splitFilePaths = null;
    let outputPath;

    try {
        splitFilePaths = getSplitFilePaths(inputFilePath);
    } catch (err) {
        // getSplitFilePaths throws if parts are missing
        throw err;
    }

    if (splitFilePaths) {
        // Split file detected - combine all parts
        console.log(`Detected split file with ${splitFilePaths.length} parts`);
        inputStream = new CombineSplitFilesReadable(splitFilePaths);

        // Output path based on the base path (remove _XXYY.b64.txt suffix)
        const parsed = parseSplitFileName(inputFilePath);
        outputPath = parsed.basePath;
    } else {
        // Single file
        inputStream = createReadStream(inputFilePath, { encoding: 'utf8', highWaterMark: CHUNK_SIZE });
        outputPath = inputFilePath.replace('.b64.txt', '');
    }

    // Create combined header extraction + decryption stream
    const headerAndDecryptStream = new HeaderAndDecryptTransform(password);

    // Use .tmp extension during decode to avoid incomplete files with final name
    const tempPath = outputPath + '.tmp';

    try {
        // Single streaming pipeline: read → base64 decode → header+decrypt → output
        await pipeline(
            inputStream,
            new Base64DecodeTransform(),
            headerAndDecryptStream,
            createWriteStream(tempPath)
        );

        // Get final output path with extension
        const header = headerAndDecryptStream.getHeader();
        const finalPath = outputPath + header.extension;

        // Rename temp file to final path with proper extension
        renameSync(tempPath, finalPath);
        outputPath = finalPath;

        if (splitFilePaths) {
            console.log(`Decoded: ${splitFilePaths.length} split files -> ${outputPath}`);
        } else {
            console.log(`Decoded: ${inputFilePath} -> ${outputPath}`);
        }
        // console.log(`  Size: ${header.fileSize} bytes`);
        // console.log(`  Cipher: ChaCha20-Poly1305`);
    } catch (err) {
        console.error(`Error during decoding: ${err.message}`);

        // Delete temp file if decode failed
        try {
            if (existsSync(tempPath)) {
                unlinkSync(tempPath);
                console.error(`Deleted incomplete temp file: ${tempPath}`);
            }
        } catch (unlinkErr) {
            // Ignore cleanup errors
        }

        process.exit(1);
    }
};

/**
 * Main entry point
 * Parses CLI arguments and routes to encode or decode function
 */
const main = async () => {
    try {
        const { decode, filePath, password, maxSize } = parseArgs();

        // Password priority: CLI flag > Environment variable > Default only
        let userPassword = password;
        if (!userPassword && process.env.B64_ECRY_PASSWORD) {
            userPassword = process.env.B64_ECRY_PASSWORD;
        }

        // Concatenate user password with default password if provided
        const finalPassword = userPassword ? userPassword + DEFAULT_PASSWORD : DEFAULT_PASSWORD;

        if (decode) {
            if (maxSize) {
                console.error('Error: --size option cannot be used when decoding');
                process.exit(1);
            }
            await decodeFile(filePath, finalPassword);
        } else {
            await encodeFile(filePath, finalPassword, maxSize);
        }
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

// Run the program
main();
