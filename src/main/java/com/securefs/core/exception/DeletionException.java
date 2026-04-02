package com.securefs.core.exception;

/**
 * Thrown when a secure deletion operation fails.
 * The file may or may not have been deleted when this is thrown.
 * The DeletionResult is not returned in this case — the exception
 * itself indicates a failure state.
 */
public class DeletionException extends SecureFileException {

    public DeletionException(String message) {
        super(message);
    }

    public DeletionException(String message, Throwable cause) {
        super(message, cause);
    }
}