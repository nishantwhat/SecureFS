package com.securefs.core.exception;

/**
 * Thrown when an encryption or decryption operation fails.
 *
 * Common causes:
 * - Wrong password (GCM authentication tag does not verify)
 * - Corrupted or tampered ciphertext
 * - Malformed encrypted file (wrong header format)
 */
public class CryptoException extends SecureFileException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}