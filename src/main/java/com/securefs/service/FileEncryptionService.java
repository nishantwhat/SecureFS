package com.securefs.service;

import com.securefs.core.exception.CryptoException;
import com.securefs.core.interfaces.EncryptionStrategy;
import com.securefs.core.model.EncryptionResult;
import com.securefs.crypto.Pbkdf2KeyDerivationService;
import com.securefs.profile.SecurityProfile;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 * Orchestrates file encryption and decryption.
 *
 * This class ties together:
 * - PBKDF2 key derivation (password → AES key)
 * - AES-256-GCM encryption/decryption
 * - File format handling (salt + profile ID in the header)
 *
 * This is the class a UI or external caller will use.
 * It exposes simple, high-level methods and hides all
 * cryptographic details behind clean interfaces.
 *
 * FILE FORMAT PRODUCED:
 * [ version: 1B ] [ profileId: 1B ] [ salt: 16B ] [ nonce: 12B ] [ ciphertext + tag ]
 *
 * The version and profileId are written by this class.
 * The nonce is written by AesGcmEncryptionStrategy inside the ciphertext stream.
 */
public class FileEncryptionService {

    // Current file format version. Increment this if the header layout changes.
    // Old files remain decryptable because the version byte is read first.
    private static final byte FILE_FORMAT_VERSION = 0x01;

    // Salt length in bytes. 16 bytes = 128 bits, as recommended by NIST SP 800-132.
    private static final int SALT_LENGTH_BYTES = 16;

    private final EncryptionStrategy encryptionStrategy;
    private final Pbkdf2KeyDerivationService kdfService;
    private final SecureRandom secureRandom;

    public FileEncryptionService(EncryptionStrategy encryptionStrategy,
                                 Pbkdf2KeyDerivationService kdfService,
                                 SecureRandom secureRandom) {
        this.encryptionStrategy = encryptionStrategy;
        this.kdfService = kdfService;
        this.secureRandom = secureRandom;
    }

    /**
     * Encrypts a file and writes the result to the output path.
     *
     * The output file includes the security profile ID and salt in a
     * plaintext header. These are not secret — they are required for
     * decryption and do not weaken security.
     *
     * The password array is zeroed by the KDF service after key derivation.
     * Do not reuse the password array after calling this method.
     *
     * @param inputPath   path to the plaintext file to encrypt
     * @param outputPath  path where the encrypted file will be written
     * @param password    the user's password as a char array (will be zeroed)
     * @param profile     the security profile controlling KDF strength and hash
     * @return EncryptionResult describing the output file and parameters used
     * @throws CryptoException if encryption fails
     * @throws IOException     if the input or output file cannot be accessed
     */
    public EncryptionResult encryptFile(Path inputPath, Path outputPath,
                                        char[] password, SecurityProfile profile)
            throws CryptoException, IOException {

        // Generate a random salt for this encryption.
        // The salt is unique per file — never reused, never derived from the password.
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);

        // Derive the AES-256 key from the password and salt.
        // The password array is zeroed inside this call.
        SecretKey key = kdfService.deriveKey(password, salt, profile.getKdfStrength());

        // Write the header and then the encrypted content.
        try (InputStream plaintext = new BufferedInputStream(Files.newInputStream(inputPath));
             OutputStream output = new BufferedOutputStream(Files.newOutputStream(outputPath))) {

            // Write the file format header.
            output.write(FILE_FORMAT_VERSION);
            output.write(profile.getProfileId());
            output.write(salt);

            // Delegate encryption to the strategy. It writes the nonce + ciphertext.
            encryptionStrategy.encrypt(plaintext, output, key);
        }

        return new EncryptionResult(outputPath, profile.name(), encryptionStrategy.getAlgorithmIdentifier());
    }

    /**
     * Decrypts a SecureFS-encrypted file and writes the plaintext to the output path.
     *
     * The security profile is read from the file header automatically.
     * The user does not need to remember or specify which profile was used.
     *
     * If the wrong password is provided, or if the file has been tampered with,
     * this method throws CryptoException and no output file is produced.
     *
     * @param inputPath   path to the encrypted file
     * @param outputPath  path where the decrypted file will be written
     * @param password    the user's password as a char array (will be zeroed)
     * @throws CryptoException if decryption or authentication fails
     * @throws IOException     if the input or output file cannot be accessed
     */
    public void decryptFile(Path inputPath, Path outputPath, char[] password)
            throws CryptoException, IOException {

        try (InputStream input = new BufferedInputStream(Files.newInputStream(inputPath))) {

            // Step 1: Read and validate the file format version.
            int version = input.read();
            if (version != FILE_FORMAT_VERSION) {
                throw new CryptoException(
                    "Unsupported file format version: " + version +
                    ". This file may have been created with a different version of SecureFS."
                );
            }

            // Step 2: Read the profile ID and reconstruct the original profile.
            // This tells us which KDF iteration count was used during encryption.
            int profileIdInt = input.read();
            if (profileIdInt == -1) {
                throw new CryptoException("File is truncated. Could not read profile ID.");
            }
            SecurityProfile profile = SecurityProfile.fromId((byte) profileIdInt);

            // Step 3: Read the salt that was stored during encryption.
            byte[] salt = input.readNBytes(SALT_LENGTH_BYTES);
            if (salt.length != SALT_LENGTH_BYTES) {
                throw new CryptoException("File is truncated. Could not read salt.");
            }

            // Step 4: Derive the key using the same profile that was used for encryption.
            SecretKey key = kdfService.deriveKey(password, salt, profile.getKdfStrength());

            // Step 5: Decrypt. The strategy reads the nonce from the stream
            // and performs GCM authentication. If authentication fails,
            // CryptoException is thrown before any output is written.
            try (OutputStream output = new BufferedOutputStream(Files.newOutputStream(outputPath))) {
                encryptionStrategy.decrypt(input, output, key);
            } catch (CryptoException e) {
                // Clean up the partial output file — it must not be left on disk.
                Files.deleteIfExists(outputPath);
                throw e;
            }
        }
    }
}