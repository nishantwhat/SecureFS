package com.securefs.core.exception;

/**
 * Thrown when a file hashing operation fails.
 * Usually caused by an unreadable file or an I/O error mid-stream.
 */
public class HashException extends SecureFileException {

    public HashException(String message) {
        super(message);
    }

    public HashException(String message, Throwable cause) {
        super(message, cause);
    }
}