# SecureFS
java based file security application 

# PROJECT STRUCTURE

securefs/
├── build.gradle
├── README.md
└── src/
    └── main/
        └── java/
            └── com/
                └── securefs/
                    │
                    ├── core/                          # Interfaces, models, exceptions
                    │   ├── exception/
                    │   │   ├── SecureFileException.java
                    │   │   ├── CryptoException.java
                    │   │   ├── DeletionException.java
                    │   │   └── HashException.java
                    │   ├── model/
                    │   │   ├── DeletionResult.java
                    │   │   ├── HashResult.java
                    │   │   └── EncryptionResult.java
                    │   └── interfaces/
                    │       ├── EncryptionStrategy.java
                    │       ├── HashingStrategy.java
                    │       └── SecureDeletionStrategy.java
                    │
                    ├── profile/                       # Security profiles
                    │   ├── SecurityProfile.java
                    │   ├── HashAlgorithm.java
                    │   └── KdfStrength.java
                    │
                    ├── crypto/                        # Encryption + key derivation
                    │   ├── AesGcmEncryptionStrategy.java
                    │   └── Pbkdf2KeyDerivationService.java
                    │
                    ├── hash/                          # Hashing implementations
                    │   ├── Sha256HashingStrategy.java
                    │   └── Sha3256HashingStrategy.java
                    │
                    ├── deletion/                      # Secure deletion
                    │   └── OverwriteDeletionStrategy.java
                    │
                    ├── service/                       # Orchestration layer
                    │   ├── FileEncryptionService.java
                    │   ├── FileHashService.java
                    │   └── SecureDeletionService.java
                    │
                    ├── factory/                       # Wiring
                    │   └── SecureFileSystemFactory.java
                    │
                    └── cli/                           # Command-line interface
                        ├── Main.java
                        ├── CommandRouter.java
                        └── commands/
                            ├── EncryptCommand.java
                            ├── DecryptCommand.java
                            ├── HashCommand.java
                            ├── VerifyCommand.java
                            └── DeleteCommand.java

# Project Name

## Description
Short explanation

## Features
- Feature 1
- Feature 2

## How to Run
Steps to run the project