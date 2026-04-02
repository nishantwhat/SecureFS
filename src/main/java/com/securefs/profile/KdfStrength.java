package com.securefs.profile;

/**
 * Defines the PBKDF2 iteration count tiers used by security profiles.
 *
 * WHY ITERATIONS MATTER:
 * PBKDF2 derives a cryptographic key from a password by running a
 * pseudorandom function many times. More iterations = more time to
 * derive the key = harder for an attacker to brute-force the password.
 *
 * The iteration counts here are sourced from:
 * - STANDARD: OWASP Password Storage Cheat Sheet 2023 minimum
 * - HIGH:     OWASP recommended for sensitive data
 * - PARANOID: 2x HIGH, for maximum resistance at the cost of speed
 *
 * A modern laptop can attempt ~10 billion SHA-256 hashes per second
 * without PBKDF2. With 310,000 iterations, that drops to ~32,000
 * password attempts per second — a significant difference.
 */
public enum KdfStrength {

    STANDARD(310_000),
    HIGH(600_000),
    PARANOID(1_200_000);

    private final int iterations;

    KdfStrength(int iterations) {
        this.iterations = iterations;
    }

    public int getIterations() {
        return iterations;
    }
}