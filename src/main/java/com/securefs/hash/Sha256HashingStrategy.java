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
 * Computes a SHA-256 digest of a file using streaming.
 *
 * WHY SHA-256?
 * SHA-256 is part of the SHA-2 family (FIPS 180-4). It produces a
 * 256-bit fingerprint of any input. Even a single changed byte in
 * the input produces a completely different digest — this property
 * is called "avalanche effect" and is essential for integrity checking.
 *
 * No two different files should produce the same SHA-256 digest.
 * This property (collision resistance) has held for SHA-256 since
 * its publication. It has NOT held for MD5 (broken 2004) or SHA-1
 * (broken 2017), which is why neither appears in this system.
 */
public class Sha256HashingStrategy implements HashingStrategy {

    private static final String ALGORITHM = "SHA-256";
    private static final int BUFFER_SIZE = 8192;

    @Override
    public HashResult hash(InputStream data) throws HashException {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);

            // DigestInputStream wraps the input stream and feeds every byte
            // to the MessageDigest as it is read. This allows single-pass
            // streaming — the file is read once and hashed simultaneously.
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
            throw new HashException("SHA-256 is not available in this JVM.", e);
        } catch (IOException e) {
            throw new HashException("Failed to read file during hashing.", e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return ALGORITHM;
    }
}