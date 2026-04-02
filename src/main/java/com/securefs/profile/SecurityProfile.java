package com.securefs.profile;

/**
 * Defines the three security profiles available in SecureFS.
 *
 * A profile bundles a hash algorithm and KDF strength into a
 * named, documented configuration. Users select a profile name —
 * they never set raw cryptographic parameters.
 *
 * WHY PROFILES INSTEAD OF RAW PARAMETERS?
 * Raw parameter fields (e.g., --iterations 50000) require the user
 * to have cryptographic knowledge to make safe choices. Profiles
 * encode that knowledge and present safe, named outcomes instead.
 *
 * The profile ID (a byte) is written into the encrypted file header
 * and read back automatically on decryption. The user does not need
 * to remember or specify which profile was used.
 *
 * HOW TO ADD A NEW PROFILE:
 * Add a new enum constant with a unique profileId, a hash algorithm,
 * a KDF strength, and a description. Nothing else needs to change.
 */
public enum SecurityProfile {

    /**
     * Suitable for everyday personal files.
     * OWASP 2023 minimum recommendation.
     * Fast enough that the user does not notice key derivation delay.
     */
    STANDARD(
            (byte) 0x01,
            HashAlgorithm.SHA256,
            KdfStrength.STANDARD,
            "Standard: SHA-256, 310,000 PBKDF2 iterations. " +
            "Suitable for personal files and everyday use."
    ),

    /**
     * Suitable for sensitive documents.
     * Noticeably slower on weak hardware — approximately 1-2 seconds.
     */
    HIGH(
            (byte) 0x02,
            HashAlgorithm.SHA3_256,
            KdfStrength.HIGH,
            "High: SHA-3-256, 600,000 PBKDF2 iterations. " +
            "Suitable for sensitive documents. Slightly slower."
    ),

    /**
     * Suitable for high-value files where maximum resistance is required.
     * Expect 3-8 seconds for key derivation on average hardware.
     */
    PARANOID(
            (byte) 0x03,
            HashAlgorithm.SHA3_256,
            KdfStrength.PARANOID,
            "Paranoid: SHA-3-256, 1,200,000 PBKDF2 iterations. " +
            "Maximum resistance. Expect several seconds of key derivation."
    );

    private final byte profileId;
    private final HashAlgorithm hashAlgorithm;
    private final KdfStrength kdfStrength;
    private final String description;

    SecurityProfile(byte profileId, HashAlgorithm hashAlgorithm,
                    KdfStrength kdfStrength, String description) {
        this.profileId = profileId;
        this.hashAlgorithm = hashAlgorithm;
        this.kdfStrength = kdfStrength;
        this.description = description;
    }

    public byte getProfileId() {
        return profileId;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public KdfStrength getKdfStrength() {
        return kdfStrength;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Looks up a SecurityProfile by its stored byte ID.
     * Used when reading an encrypted file header to reconstruct
     * the original profile without user input.
     *
     * @param id the profile byte stored in the file header
     * @return the matching SecurityProfile
     * @throws IllegalArgumentException if the ID is not recognized
     */
    public static SecurityProfile fromId(byte id) {
        for (SecurityProfile profile : values()) {
            if (profile.profileId == id) {
                return profile;
            }
        }
        throw new IllegalArgumentException(
            "Unknown profile ID: 0x" + Integer.toHexString(id & 0xFF) +
            ". This file may have been created with a newer version of SecureFS."
        );
    }
}