package com.securefs.service;

import com.securefs.core.exception.HashException;
import com.securefs.core.interfaces.HashingStrategy;
import com.securefs.core.model.HashResult;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Provides file hashing and digest verification.
 *
 * Accepts any HashingStrategy — the service does not know or care
 * whether it is using SHA-256 or SHA-3-256. The strategy is injected
 * at construction time by the factory.
 */
public class FileHashService {

    private final HashingStrategy hashingStrategy;

    public FileHashService(HashingStrategy hashingStrategy) {
        this.hashingStrategy = hashingStrategy;
    }

    /**
     * Computes the digest of a file.
     *
     * @param filePath path to the file to hash
     * @return HashResult containing the digest, algorithm name, and byte count
     * @throws HashException if the file cannot be read or hashing fails
     * @throws IOException   if the file cannot be opened
     */
    public HashResult hashFile(Path filePath) throws HashException, IOException {
        try (InputStream stream = new BufferedInputStream(Files.newInputStream(filePath))) {
            return hashingStrategy.hash(stream);
        }
    }

    /**
     * Verifies a file's digest against an expected value.
     *
     * Uses MessageDigest.isEqual() for comparison, which performs a
     * constant-time comparison. This prevents timing side-channel attacks
     * where an attacker could infer partial digest matches by measuring
     * how long the comparison takes.
     *
     * @param filePath       path to the file to verify
     * @param expectedHex    the expected digest as a lowercase hexadecimal string
     * @return true if the digest matches, false otherwise
     * @throws HashException if hashing fails
     * @throws IOException   if the file cannot be opened
     */
    public boolean verifyFile(Path filePath, String expectedHex)
            throws HashException, IOException {

        HashResult result = hashFile(filePath);

        byte[] expectedBytes = HexFormat.of().parseHex(expectedHex);

        // Constant-time comparison — do not use Arrays.equals() here.
        // Arrays.equals() returns false immediately on the first mismatch,
        // which creates a timing difference measurable by an attacker.
        // MessageDigest.isEqual() always takes the same time regardless.
        return MessageDigest.isEqual(result.getDigest(), expectedBytes);
    }
}