package com.securefs.hash;

import com.securefs.core.exception.HashException;
import com.securefs.core.interfaces.HashingStrategy;
import com.securefs.core.model.HashResult;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Computes a SHA-3-256 digest of a file using streaming.
 *
 * WHY SHA-3 AS AN ALTERNATIVE?
 * SHA-3 (FIPS 202) uses a completely different internal construction
 * called a "sponge function" (Keccak). SHA-256 uses Merkle-Damgard.
 *
 * This matters because if a fundamental weakness were ever found in
 * the Merkle-Damgard construction, it would affect SHA-256 but NOT
 * SHA-3. The two algorithms are structurally independent.
 *
 * SHA-3-256 is used in the HIGH and PARANOID security profiles as
 * a conservative choice for higher-assurance use cases.
 *
 * The code here is structurally identical to Sha256HashingStrategy.
 * The only difference is the algorithm name passed to MessageDigest.
 * This is a textbook demonstration of the Strategy pattern — same
 * interface, different algorithm, zero duplication of logic.
 */
public class Sha3256HashingStrategy implements HashingStrategy {

    private static final String ALGORITHM = "SHA3-256";
    private static final int BUFFER_SIZE = 8192;

    @Override
    public HashResult hash(InputStream data) throws HashException {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);

            try (DigestInputStream digestStream = new DigestInputStream(data, digest)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                long totalBytes = 0;

                int bytesRead;
                while ((bytesRead = digestStream.read(buffer)) != -1) {
                    totalBytes += bytesRead;
                }

                return new HashResult(digest.digest(), ALGORITHM, totalBytes);
            }

        } catch (NoSuchAlgorithmException e) {
            throw new HashException(
                "SHA3-256 is not available in this JVM. Java 9+ is required.", e
            );
        } catch (IOException e) {
            throw new HashException("Failed to read file during hashing.", e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return ALGORITHM;
    }
}