# SecureFS
java based file security application 

## How the System Works — Plain Explanation
When you encrypt a file, three things happen in sequence. 
First, a random 16-byte salt is generated. Your password and that salt are fed into PBKDF2, which runs 310,000 (or more, depending on profile) rounds of a mathematical function to produce a 256-bit key. This is slow by design — it makes brute-forcing your password expensive. 

Second, a random 12-byte nonce is generated. The AES-256-GCM cipher uses the key and nonce to encrypt your file and produces a 16-byte authentication tag alongside the ciphertext. 

Third, the output file is written as: version byte, profile byte, salt, nonce, ciphertext, and tag — all in sequence.

When you decrypt, the process reverses. The version and profile bytes are read first to know which parameters were used. The salt is read and combined with your password to re-derive the exact same key. The nonce is read and given to AES-GCM along with the ciphertext. If your password is correct and the file is unmodified, the authentication tag verifies and plaintext is produced. If anything is wrong — wrong password, flipped bit, truncated file — the tag fails to verify and decryption stops with an error and no output.

Every layer in the system is independent. The CLI does not know that AES-GCM exists. The encryption engine does not know that security profiles exist. The factory connects them once. Everything else communicates through interfaces.

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

# Step-by-Step Run Guide

## Step 1: Clone and build
bash

git clone https://github.com/yourname/securefs.git
cd securefs
./gradlew jar

This produces build/libs/securefs.jar.

## Step 2: Create an alias (optional but convenient)
bash

alias securefs='java -jar /path/to/securefs/build/libs/securefs.jar'

## Step 3: Encrypt a file
bash

securefs encrypt --input secret.txt --output secret.txt.enc --profile STANDARD
 Enter password: (typed, not echoed)
 Encryption successful.
 Output:    secret.txt.enc
 Profile:   STANDARD
 Algorithm: AES-256-GCM

## Step 4: Decrypt the file
bash

securefs decrypt --input secret.txt.enc --output secret_decrypted.txt
 Enter password: (typed, not echoed)
 Decryption successful.
 Output: secret_decrypted.txt
 
## Step 5: Hash a file
bash

securefs hash --input secret.txt
 file:      secret.txt
 algorithm: SHA-256
 digest:    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 bytes:     0

## Step 6: Verify integrity
bash

securefs verify --input secret.txt --expected e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 VERIFIED: Digest matches.

## Step 7: Securely delete a file
bash

securefs delete --input secret.txt --mode SECURE
 Deleted:    secret.txt
 Confidence: UNKNOWN
 Note:       File overwritten with random bytes and deleted. On HDD: data
             is likely unrecoverable. On SSD: wear leveling may preserve
             original data in unreachable sectors.

