package com.securefs.core.interfaces;

import com.securefs.core.exception.CryptoException;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Defines the contract for all encryption and decryption strategies.
 *
 * WHY AN INTERFACE?
 * The system currently uses AES-256-GCM exclusively. In the future,
 * a new algorithm (e.g. ChaCha20-Poly1305) may be added. By coding
 * against this interface everywhere, that addition requires zero
 * changes to the service or CLI layers.
 *
 * HOW TO ADD A NEW ALGORITHM:
 * 1. Create a new class that implements this interface.
 * 2. Register it in SecureFileSystemFactory.
 * That is all.
 */
public interface EncryptionStrategy {

    /**
     * Encrypts data from the input stream and writes the result to the output stream.
     *
     * The implementation is responsible for generating and prepending the nonce.
     * The caller provides the key derived from PBKDF2 — not a raw password.
     *
     * @param plaintext  readable stream of the original file contents
     * @param ciphertext writable stream for the encrypted output
     * @param key        AES-256 secret key derived from the user's password
     * @throws CryptoException if encryption fails for any reason
     *
     * SECURITY NOTE:
     * The nonce must be randomly generated per call and never reused
     * with the same key. Nonce reuse in GCM breaks both confidentiality
     * and authentication. This must be enforced inside the implementation,
     * not left to the caller.
     */
    void encrypt(InputStream plaintext, OutputStream ciphertext, SecretKey key)
            throws CryptoException;

    /**
     * Decrypts data from the input stream and writes plaintext to the output stream.
     *
     * The implementation reads the nonce from the start of the ciphertext stream.
     * If the GCM authentication tag does not verify, this method throws
     * CryptoException and no plaintext is written.
     *
     * @param ciphertext readable stream of the encrypted file contents
     * @param plaintext  writable stream for the decrypted output
     * @param key        AES-256 secret key derived from the user's password
     * @throws CryptoException if decryption fails or authentication tag is invalid
     */
    void decrypt(InputStream ciphertext, OutputStream plaintext, SecretKey key)
            throws CryptoException;

    /**
     * Returns a short identifier for this algorithm.
     * Stored in the encrypted file header for future compatibility.
     *
     * Example: "AES-256-GCM"
     *
     * @return algorithm identifier string
     */
    String getAlgorithmIdentifier();
}