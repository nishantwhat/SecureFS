package com.securefs.profile;

/**
 * Enumerates the hashing algorithms available in SecureFS.
 *
 * Only algorithms with no known practical attacks are included.
 * MD5 and SHA-1 are intentionally absent.
 *
 * algorithmName is the exact string passed to MessageDigest.getInstance().
 */
public enum HashAlgorithm {

    /**
     * SHA-256 — FIPS 180-4.
     * Default choice. Widely supported. Fast on all hardware.
     */
    SHA256("SHA-256"),

    /**
     * SHA-3-256 — FIPS 202 (Keccak sponge construction).
     * Structurally different from SHA-256. Resistant to length
     * extension attacks. Used in HIGH and PARANOID profiles.
     */
    SHA3_256("SHA3-256");

    private final String algorithmName;

    HashAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }
}