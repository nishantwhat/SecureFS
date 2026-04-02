package com.securefs.core.model;

/**
 * Carries the result of a secure deletion operation.
 *
 * The Confidence enum is the key design element here.
 * Instead of silently claiming success, the system reports
 * HOW confident it is that the data is truly unrecoverable.
 *
 * This is especially important for SSD storage where overwrite-based
 * deletion cannot guarantee physical data erasure.
 */
public final class DeletionResult {

    /**
     * Represents how confident the system is that the file data
     * is unrecoverable after deletion.
     *
     * HIGH   — HDD confirmed. Overwrite reliably reaches the original sectors.
     * MEDIUM — File was encrypted before deletion. Even residual data is ciphertext.
     * LOW    — SSD detected. Wear leveling may have preserved original data.
     * UNKNOWN — Storage type could not be determined.
     */
    public enum Confidence {
        HIGH, MEDIUM, LOW, UNKNOWN
    }

    private final boolean deleted;
    private final Confidence confidence;
    private final String explanation;

    public DeletionResult(boolean deleted, Confidence confidence, String explanation) {
        this.deleted = deleted;
        this.confidence = confidence;
        this.explanation = explanation;
    }

    public boolean isDeleted() {
        return deleted;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public String getExplanation() {
        return explanation;
    }
}