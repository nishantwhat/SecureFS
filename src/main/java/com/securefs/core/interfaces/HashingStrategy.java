package com.securefs.core.interfaces;

import com.securefs.core.exception.HashException;
import com.securefs.core.model.HashResult;

import java.io.InputStream;

/**
 * Defines the contract for all file hashing strategies.
 *
 * Both SHA-256 and SHA-3-256 implement this interface.
 * The FileHashService does not know which one it is using —
 * it only calls this interface. Swapping or adding algorithms
 * requires no changes to the service.
 */
public interface HashingStrategy {

    /**
     * Reads the entire input stream and produces a cryptographic digest.
     *
     * Uses streaming to handle files of any size without loading
     * the whole file into memory.
     *
     * @param data readable stream of the file to hash
     * @return HashResult containing the digest bytes and algorithm name
     * @throws HashException if reading or hashing fails
     */
    HashResult hash(InputStream data) throws HashException;

    /**
     * Returns the algorithm name used by this strategy.
     * Example: "SHA-256", "SHA3-256"
     *
     * @return algorithm name string
     */
    String getAlgorithmName();
}