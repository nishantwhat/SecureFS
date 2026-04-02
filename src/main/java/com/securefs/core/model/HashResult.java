package com.securefs.core.model;

import java.util.HexFormat;

/**
 * Carries the result of a file hashing operation.
 *
 * Immutable — created once by the hashing strategy and passed up
 * to the service and CLI layers without modification.
 */
public final class HashResult {

    private final byte[] digest;
    private final String algorithmName;
    private final long bytesProcessed;

    public HashResult(byte[] digest, String algorithmName, long bytesProcessed) {
        // Defensive copy so the caller cannot mutate the internal array
        this.digest = digest.clone();
        this.algorithmName = algorithmName;
        this.bytesProcessed = bytesProcessed;
    }

    /** Returns the raw digest bytes. */
    public byte[] getDigest() {
        return digest.clone();
    }

    /** Returns the digest as a lowercase hexadecimal string. */
    public String getDigestHex() {
        return HexFormat.of().formatHex(digest);
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public long getBytesProcessed() {
        return bytesProcessed;
    }
}