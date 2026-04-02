package com.securefs.crypto;

import com.securefs.core.exception.CryptoException;
import com.securefs.core.interfaces.EncryptionStrategy;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Encrypts and decrypts files using AES-256-GCM.
 *
 * WHY AES-256-GCM?
 * AES (Advanced Encryption Standard) is the global standard for
 * symmetric encryption, approved by NIST. The 256-bit key size
 * provides a 128-bit security level against brute-force attacks.
 *
 * GCM (Galois/Counter Mode) is what makes this "authenticated encryption."
 * It does two things simultaneously:
 *   1. Encrypts the data (confidentiality — nobody can read it)
 *   2. Produces an authentication tag (integrity — any tampering is detected)
 *
 * Without authentication, an attacker could flip bits in the ciphertext
 * and the decryption would silently produce corrupted output. With GCM,
 * a single changed byte causes decryption to fail with an error.
 *
 * WHY NOT AES-CBC?
 * CBC (Cipher Block Chaining) provides confidentiality only. Without a
 * separate HMAC, CBC ciphertext can be manipulated in predictable ways
 * (padding oracle attacks). GCM eliminates this entire attack class.
 *
 * FILE FORMAT WRITTEN BY THIS CLASS:
 * [ nonce: 12 bytes ] [ ciphertext + GCM tag: variable ]
 *
 * The nonce is written in plaintext before the ciphertext. It is not
 * secret — it just must never be reused with the same key.
 *
 * STANDARD REFERENCE: NIST SP 800-38D
 */
public class AesGcmEncryptionStrategy implements EncryptionStrategy {

    // GCM nonces must be exactly 96 bits (12 bytes) per NIST SP 800-38D.
    private static final int NONCE_LENGTH_BYTES = 12;

    // The authentication tag length. 128 bits is the maximum and is required.
    // A shorter tag weakens the integrity guarantee.
    private static final int GCM_TAG_LENGTH_BITS = 128;

    // Buffer size for streaming. 8KB is a standard choice — large enough
    // to be efficient, small enough to avoid excessive memory use on large files.
    private static final int BUFFER_SIZE = 8192;

    private static final String ALGORITHM = "AES/GCM/NoPadding";

    // SecureRandom is the only acceptable source of randomness for cryptography.
    // java.util.Random is predictable and must never be used for security purposes.
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public void encrypt(InputStream plaintext, OutputStream ciphertext, SecretKey key)
            throws CryptoException {

        // Step 1: Generate a fresh random nonce for this encryption.
        // This MUST be unique per (key, nonce) pair. We generate it randomly
        // with 96 bits of entropy — the probability of collision is negligible.
        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        secureRandom.nextBytes(nonce);

        try {
            // Step 2: Write the nonce to the output first.
            // The decryption side reads this before initializing the cipher.
            ciphertext.write(nonce);

            // Step 3: Initialize the cipher in encryption mode.
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            // Step 4: Stream the plaintext through the cipher in chunks.
            // This handles files of any size without loading them into memory.
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = plaintext.read(buffer)) != -1) {
                byte[] encryptedChunk = cipher.update(buffer, 0, bytesRead);
                if (encryptedChunk != null) {
                    ciphertext.write(encryptedChunk);
                }
            }

            // Step 5: Finalize the cipher.
            // For GCM, this appends the 16-byte authentication tag to the output.
            byte[] finalChunk = cipher.doFinal();
            ciphertext.write(finalChunk);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException("AES-GCM algorithm not available in this JVM.", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Invalid key or parameters for AES-GCM.", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("AES-GCM encryption failed during finalization.", e);
        } catch (IOException e) {
            throw new CryptoException("I/O error during encryption.", e);
        }
    }

    @Override
    public void decrypt(InputStream ciphertext, OutputStream plaintext, SecretKey key)
            throws CryptoException {

        try {
            // Step 1: Read the nonce from the start of the ciphertext stream.
            // This must match exactly what was written during encryption.
            byte[] nonce = ciphertext.readNBytes(NONCE_LENGTH_BYTES);
            if (nonce.length != NONCE_LENGTH_BYTES) {
                throw new CryptoException(
                    "File is too short to contain a valid nonce. " +
                    "The file may be corrupted or not a SecureFS file."
                );
            }

            // Step 2: Initialize the cipher in decryption mode using the stored nonce.
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            // Step 3: Stream the ciphertext through the cipher.
            // GCM buffers internally during streaming and only verifies the
            // authentication tag at doFinal(). No plaintext is written until
            // the entire ciphertext has been processed and verified.
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = ciphertext.read(buffer)) != -1) {
                byte[] decryptedChunk = cipher.update(buffer, 0, bytesRead);
                if (decryptedChunk != null) {
                    plaintext.write(decryptedChunk);
                }
            }

            // Step 4: doFinal() verifies the GCM authentication tag.
            // If any byte of the ciphertext was modified — wrong password,
            // corrupted file, or tampering — this throws AEADBadTagException.
            // The caller receives a CryptoException and no partial output is used.
            byte[] finalChunk = cipher.doFinal();
            plaintext.write(finalChunk);

        } catch (AEADBadTagException e) {
            // This is the most important exception in the system.
            // It means: wrong password, tampered file, or corrupted data.
            // The message must be clear enough for the user to act on.
            throw new CryptoException(
                "Decryption failed: the file could not be authenticated. " +
                "Possible causes: wrong password, corrupted file, or tampered ciphertext.", e
            );
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException("AES-GCM algorithm not available in this JVM.", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Invalid key or parameters for AES-GCM.", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("AES-GCM decryption failed during finalization.", e);
        } catch (IOException e) {
            throw new CryptoException("I/O error during decryption.", e);
        }
    }

    @Override
    public String getAlgorithmIdentifier() {
        return "AES-256-GCM";
    }
}