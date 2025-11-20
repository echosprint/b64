#!/usr/bin/env node

/**
 * b64 - Base64 encoder/decoder with simple obfuscation
 *
 * Encodes files to base64 with XOR obfuscation and file extension preservation.
 * Uses streaming to handle large files (5GB+) without loading into memory.
 *
 * Usage:
 *   Encode: node b64.mjs <file>
 *   Decode: node b64.mjs -d <file.b64.txt>
 */

import { createReadStream, createWriteStream } from 'fs';
import { parse as parsePath } from 'path';
import { Transform, pipeline } from 'stream';
import { promisify } from 'util';

// Convert callback-based pipeline to Promise-based for async/await
const pipelineAsync = promisify(pipeline);

/**
 * Parse command line arguments
 * Supports: -d/--decode flag, -f/--file option, or positional file argument
 * @returns {Object} { decode: boolean, filePath: string }
 */
const parseArgs = () => {
    const args = process.argv.slice(2);
    let decode = false;
    let filePath = null;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-d' || args[i] === '--decode') {
            decode = true;
        } else if (args[i] === '-f' || args[i] === '--file') {
            filePath = args[i + 1];
            i++; // Skip next arg since we consumed it
        } else if (!args[i].startsWith('-')) {
            filePath = args[i]; // Positional argument
        }
    }

    if (!filePath) {
        console.error('Error: File path is required');
        console.log('Usage: node b64.js [-d|--decode] [-f|--file] <file_path>');
        process.exit(1);
    }

    return { decode, filePath };
};

/**
 * Transform stream to apply simple obfuscation to bytes
 * Adds 0xAA (170) to each byte modulo 256
 * NOTE: This is NOT real encryption, just simple obfuscation
 */
class EncryptTransform extends Transform {
    _transform = (chunk, encoding, callback) => {
        const encrypted = Buffer.alloc(chunk.length);
        for (let i = 0; i < chunk.length; i++) {
            encrypted[i] = (chunk[i] + 0xAA) % 256;
        }
        this.push(encrypted);
        callback();
    };
}

/**
 * Transform stream to reverse the obfuscation
 * Subtracts 0xAA (170) from each byte modulo 256
 */
class DecryptTransform extends Transform {
    _transform = (chunk, encoding, callback) => {
        const decrypted = Buffer.alloc(chunk.length);
        for (let i = 0; i < chunk.length; i++) {
            decrypted[i] = (chunk[i] + 256 - 0xAA) % 256;
        }
        this.push(decrypted);
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

    _transform = (chunk, encoding, callback) => {
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

    _transform = (chunk, encoding, callback) => {
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
 * Transform stream to extract and skip the file extension prefix during decoding
 *
 * File format prefix:
 *   Byte 0: Length of prefix (extension length + 1)
 *   Bytes 1-N: Extension string (e.g., ".txt", ".jpg")
 *   Bytes N+: Actual file content
 *
 * This stream extracts the extension and passes through only the file content
 */
class PrefixSkipTransform extends Transform {
    prefixProcessed = false; // Whether we've extracted the prefix yet
    prefixLen = null;        // Length of the prefix to skip
    extension = null;        // Extracted file extension
    buffer = Buffer.alloc(0); // Accumulate data until we can read the full prefix

    _transform = (chunk, encoding, callback) => {
        if (!this.prefixProcessed) {
            // Accumulate chunks until we have enough data to read the prefix
            this.buffer = Buffer.concat([this.buffer, chunk]);

            if (this.buffer.length >= 1) {
                // First byte tells us the total prefix length
                this.prefixLen = this.buffer[0];

                if (this.buffer.length >= this.prefixLen) {
                    // Extract the extension string (bytes 1 to prefixLen-1)
                    this.extension = this.buffer.toString('utf8', 1, this.prefixLen);

                    // Push the actual file content (after the prefix)
                    const content = this.buffer.subarray(this.prefixLen);
                    if (content.length > 0) {
                        this.push(content);
                    }

                    this.prefixProcessed = true;
                    this.buffer = null; // Free memory
                    callback();
                    return;
                }
            }
            // Not enough data yet, wait for more chunks
            callback();
        } else {
            // Prefix already extracted, just pass through remaining data
            this.push(chunk);
            callback();
        }
    };

    getExtension = () => this.extension;
}

/**
 * Transform stream that prepends a prefix buffer before the file content
 * Used during encoding to add the file extension prefix
 */
class PrependTransform extends Transform {
    prefixSent = false; // Track if we've sent the prefix yet

    constructor(prefixBuffer, options) {
        super(options);
        this.prefixBuffer = prefixBuffer;
    }

    _transform = (chunk, encoding, callback) => {
        if (!this.prefixSent) {
            // Send prefix before first chunk of file data
            this.push(this.prefixBuffer);
            this.prefixSent = true;
        }
        this.push(chunk);
        callback();
    };
}

/**
 * Encode a file to base64 with obfuscation
 *
 * Process flow:
 *   1. Read file in 64KB chunks (streaming)
 *   2. Prepend extension prefix (e.g., [5, '.', 't', 'x', 't'])
 *   3. Apply obfuscation (add 0xAA to each byte)
 *   4. Base64 encode
 *   5. Write to .b64.txt file
 *
 * @param {string} inputFilePath - Path to file to encode
 */
const encodeFile = async (inputFilePath) => {
    // Extract file extension (keep typo "extention" to match Rust version)
    const { ext: extention } = parsePath(inputFilePath);
    const prefixLen = extention.length + 1;

    // Create prefix buffer: [length_byte, extension_chars...]
    const prefixBuffer = Buffer.alloc(1 + extention.length);
    prefixBuffer[0] = prefixLen;
    prefixBuffer.write(extention, 1, extention.length, 'utf8');

    const outputPath = inputFilePath.replace(extention, '') + '.b64.txt';

    // Create streaming pipeline (64KB chunks for memory efficiency)
    const inputStream = createReadStream(inputFilePath, { highWaterMark: 64 * 1024 });
    const prependStream = new PrependTransform(prefixBuffer);
    const encryptStream = new EncryptTransform();
    const base64Stream = new Base64EncodeTransform();
    const outputStream = createWriteStream(outputPath);

    try {
        // Pipeline: input -> prepend prefix -> encrypt -> base64 -> output
        await pipelineAsync(
            inputStream,
            prependStream,
            encryptStream,
            base64Stream,
            outputStream
        );
        console.log(`Encoded: ${inputFilePath} -> ${outputPath}`);
    } catch (err) {
        console.error(`Error during encoding: ${err.message}`);
        process.exit(1);
    }
};

/**
 * Custom transform stream that dynamically creates output file based on extracted extension
 *
 * Problem: We don't know the output filename until we've decoded and extracted the extension
 * Solution: Create the output file stream on the first data chunk, after extension is known
 */
class DynamicFileWriter extends Transform {
    outputStream = null;  // File stream (created after we know the extension)
    outputPath = null;    // Output filename (determined from extracted extension)
    firstChunk = true;    // Track if this is the first chunk

    constructor(inputFilePath, options) {
        super(options);
        this.inputFilePath = inputFilePath;
    }

    _transform = (chunk, encoding, callback) => {
        if (this.firstChunk && this.prefixSkipStream) {
            this.firstChunk = false;

            // Get the extension that was extracted from the prefix
            const extention = this.prefixSkipStream.getExtension();

            // Create output filename: input.b64.txt -> input.ext
            this.outputPath = this.inputFilePath.replace('.b64.txt', '') + extention;

            // Now we can create the output file stream
            this.outputStream = createWriteStream(this.outputPath);
        }

        // Write decoded data to the output file
        if (this.outputStream) {
            this.outputStream.write(chunk);
        }
        callback();
    };

    _flush = (callback) => {
        // Close the output file when stream ends
        if (this.outputStream) {
            this.outputStream.end(() => {
                console.log(`Decoded: ${this.inputFilePath} -> ${this.outputPath}`);
                callback();
            });
        } else {
            callback();
        }
    };

    setPrefixSkipStream = (stream) => {
        this.prefixSkipStream = stream;
    };
}

/**
 * Decode a .b64.txt file back to its original format
 *
 * Process flow:
 *   1. Read .b64.txt file in 64KB chunks (streaming)
 *   2. Base64 decode
 *   3. Apply de-obfuscation (subtract 0xAA from each byte)
 *   4. Extract extension from prefix
 *   5. Write to original filename with correct extension
 *
 * @param {string} inputFilePath - Path to .b64.txt file to decode
 */
const decodeFile = async (inputFilePath) => {
    // Validate input file extension
    if (!inputFilePath.endsWith('.b64.txt')) {
        throw new Error('Only can decode file end with .b64.txt file');
    }

    // Create streaming pipeline (read as UTF-8 text for base64)
    const inputStream = createReadStream(inputFilePath, { encoding: 'utf8', highWaterMark: 64 * 1024 });
    const base64DecodeStream = new Base64DecodeTransform();
    const decryptStream = new DecryptTransform();
    const prefixSkipStream = new PrefixSkipTransform();
    const fileWriter = new DynamicFileWriter(inputFilePath);

    // Link the prefix extractor to the file writer so it knows the output extension
    fileWriter.setPrefixSkipStream(prefixSkipStream);

    try {
        // Pipeline: input -> base64 decode -> decrypt -> extract prefix -> write file
        await pipelineAsync(
            inputStream,
            base64DecodeStream,
            decryptStream,
            prefixSkipStream,
            fileWriter
        );
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
