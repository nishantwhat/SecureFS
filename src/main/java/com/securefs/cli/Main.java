package com.securefs.cli;

/**
 * Entry point for the SecureFS command-line interface.
 *
 * This class does exactly one thing: hand off to CommandRouter.
 * No logic lives here. This separation means the router can be
 * tested independently and the entry point stays trivially simple.
 *
 * UI INTEGRATION NOTE:
 * A UI does not go through Main or CommandRouter at all.
 * It imports the service layer directly:
 *
 *   FileEncryptionService service = SecureFileSystemFactory.createEncryptionService();
 *   service.encryptFile(...);
 *
 * Main and CommandRouter are CLI concerns only.
 */
public class Main {

    public static void main(String[] args) {
        new CommandRouter().route(args);
    }
}