package com.securefs.core.exception;

/**
 * Root exception for all SecureFS operational failures.
 *
 * All exceptions in this system extend this class.
 * Callers that want to catch any SecureFS error in one place
 * can catch SecureFileException. Callers that want to handle
 * specific failure types (crypto vs I/O) catch the subclasses.
 *
 * These are checked exceptions — callers must explicitly handle
 * or declare them. This is intentional: security operations fail
 * in meaningful ways that the caller must acknowledge.
 */
public class SecureFileException extends Exception {

    public SecureFileException(String message) {
        super(message);
    }

    public SecureFileException(String message, Throwable cause) {
        super(message, cause);
    }
}