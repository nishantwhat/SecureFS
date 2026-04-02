package com.securefs.cli;

import com.securefs.cli.commands.*;

/**
 * Routes a parsed command name to the correct command handler.
 *
 * This class is the only place that knows all command names.
 * Adding a new command means: create a new Command class,
 * add one case here, and add usage text to printUsage().
 * Nothing else changes.
 */
public class CommandRouter {

    /**
     * Routes and executes the command based on parsed arguments.
     *
     * Expected argument formats:
     *
     *   encrypt --input <file> --output <file> [--profile STANDARD|HIGH|PARANOID]
     *   decrypt --input <file> --output <file>
     *   hash    --input <file> [--algorithm SHA256|SHA3_256]
     *   verify  --input <file> --expected <hex> [--algorithm SHA256|SHA3_256]
     *   delete  --input <file> [--mode SECURE|NORMAL]
     *
     * @param args the full args array from main(), including the command name
     */
    public void route(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        String command = args[0].toLowerCase();

        switch (command) {
            case "encrypt" -> handleEncrypt(args);
            case "decrypt" -> handleDecrypt(args);
            case "hash"    -> handleHash(args);
            case "verify"  -> handleVerify(args);
            case "delete"  -> handleDelete(args);
            default -> {
                System.err.println("Unknown command: " + command);
                printUsage();
                System.exit(1);
            }
        }
    }

    private void handleEncrypt(String[] args) {
        String input   = getArg(args, "--input");
        String output  = getArg(args, "--output");
        String profile = getArgOrDefault(args, "--profile", "STANDARD");
        requireArgs(input, "--input");
        requireArgs(output, "--output");
        new EncryptCommand().execute(input, output, profile);
    }

    private void handleDecrypt(String[] args) {
        String input  = getArg(args, "--input");
        String output = getArg(args, "--output");
        requireArgs(input, "--input");
        requireArgs(output, "--output");
        new DecryptCommand().execute(input, output);
    }

    private void handleHash(String[] args) {
        String input     = getArg(args, "--input");
        String algorithm = getArgOrDefault(args, "--algorithm", "SHA256");
        requireArgs(input, "--input");
        new HashCommand().execute(input, algorithm);
    }

    private void handleVerify(String[] args) {
        String input     = getArg(args, "--input");
        String expected  = getArg(args, "--expected");
        String algorithm = getArgOrDefault(args, "--algorithm", "SHA256");
        requireArgs(input, "--input");
        requireArgs(expected, "--expected");
        new VerifyCommand().execute(input, expected, algorithm);
    }

    private void handleDelete(String[] args) {
        String input = getArg(args, "--input");
        String mode  = getArgOrDefault(args, "--mode", "SECURE");
        requireArgs(input, "--input");
        new DeleteCommand().execute(input, mode);
    }

    /**
     * Finds the value following a named argument flag.
     * Returns null if the flag is not present.
     *
     * Example: getArg(["--input", "file.txt"], "--input") → "file.txt"
     */
    private String getArg(String[] args, String flag) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase(flag)) {
                return args[i + 1];
            }
        }
        return null;
    }

    private String getArgOrDefault(String[] args, String flag, String defaultValue) {
        String value = getArg(args, flag);
        return (value != null) ? value : defaultValue;
    }

    private void requireArgs(String value, String flagName) {
        if (value == null || value.isBlank()) {
            System.err.println("Error: Missing required argument: " + flagName);
            printUsage();
            System.exit(1);
        }
    }

    private void printUsage() {
        System.out.println("""
            SecureFS — Secure File Handling System
            
            Usage: securefs <command> [options]
            
            Commands:
              encrypt  --input <file> --output <file> [--profile STANDARD|HIGH|PARANOID]
              decrypt  --input <file> --output <file>
              hash     --input <file> [--algorithm SHA256|SHA3_256]
              verify   --input <file> --expected <hex> [--algorithm SHA256|SHA3_256]
              delete   --input <file> [--mode SECURE|NORMAL]
            
            Profiles:
              STANDARD  SHA-256,   310,000 PBKDF2 iterations (default)
              HIGH      SHA3-256,  600,000 PBKDF2 iterations
              PARANOID  SHA3-256, 1200,000 PBKDF2 iterations
            """);
    }
}