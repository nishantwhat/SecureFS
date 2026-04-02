package com.securefs.crypto;

import com.securefs.core.exception.CryptoException;
import com.securefs.profile.KdfStrength;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Derives a 256-bit AES key from a user password using PBKDF2-HMAC-SHA256.
 *
 * WHY PBKDF2?
 * Passwords are weak secrets. A typical password has far less entropy
 * than a proper cryptographic key. If you use a password directly as
 * an AES key, an attacker can brute-force it very quickly.
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) solves this by
 * deliberately slowing down the key derivation process. It runs the
 * password through HMAC-SHA256 thousands of times. This does not stop
 * brute-force attacks, but it makes each attempt thousands of times
 * more expensive.
 *
 * WHY A SALT?
 * Without a salt, two users with the same password would produce the
 * same key. An attacker could precompute keys for common passwords
 * (a "rainbow table" attack). A unique random salt per file means
 * the attacker must redo the work for every single file.
 *
 * STANDARD REFERENCE: NIST SP 800-132
 */
public class Pbkdf2KeyDerivationService {

    // The PBKDF2 variant that uses HMAC-SHA256 as the pseudorandom function.
    // This is what NIST recommends and what OWASP bases its iteration count on.
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    // AES requires a 256-bit key. This is fixed — not configurable.
    private static final int KEY_LENGTH_BITS = 256;

    /**
     * Derives a 256-bit AES SecretKey from a password and salt.
     *
     * The caller provides the KDF strength (iteration count) via the
     * security profile. The salt must be randomly generated and unique
     * per file — it is never derived from the password or filename.
     *
     * IMPORTANT: This method zeros the password array after use.
     * Never pass a char[] that you still need after this call.
     *
     * @param password     the user's password as a char array (will be zeroed)
     * @param salt         a randomly generated 16-byte salt unique to this file
     * @param kdfStrength  the iteration count tier from the security profile
     * @return a 256-bit AES SecretKey ready for use with AES-GCM
     * @throws CryptoException if the JVM does not support PBKDF2WithHmacSHA256
     */
    public SecretKey deriveKey(char[] password, byte[] salt, KdfStrength kdfStrength)
            throws CryptoException {

        // PBEKeySpec holds the password, salt, iteration count, and desired key length.
        // We use char[] for the password — never String — because char[] can be zeroed.
        // Java Strings are immutable and may persist in the string pool.
        PBEKeySpec keySpec = new PBEKeySpec(
                password,
                salt,
                kdfStrength.getIterations(),
                KEY_LENGTH_BITS
        );

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();

            // Wrap the raw key bytes into a SecretKeySpec for use with AES-GCM.
            return new SecretKeySpec(keyBytes, "AES");

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(
                "Key derivation failed. PBKDF2WithHmacSHA256 is required but unavailable.", e
            );
        } finally {
            // Always zero the key spec — it holds a copy of the password.
            // This runs even if an exception is thrown.
            keySpec.clearPassword();

            // Zero the original password array passed by the caller.
            Arrays.fill(password, '\0');
        }
    }
}