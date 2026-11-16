# Code Challenge

Three small Java command-line applications:

1. **KeyGen** – generates an RSA key pair (2048 bits)
2. **HashFile** – prints the SHA-256 hash of a file in hex
3. **FileCrypto** – encrypts and decrypts a file using the RSA key pair

Only the standard Java library is used. No external libraries.

## Requirements

- Java 17 or newer (tested with Java 21)

Check with:

```
java -version
```

## Folder structure

```
src/        KeyGen.java, HashFile.java, FileCrypto.java
keys/       public_key.pem, private_key.pem
files/      AMD image file.JPG       (original file)
            AMD image file.JPG.enc   (encrypted file)
```

The private key is sent by email only. It is not stored in the GitHub repository.

## How to run

Run all commands from the project folder (the folder that contains `src`).
Each program runs directly from its source file; no separate compile step is needed.
File names with spaces must be in quotes.

### 1. Generate the RSA key pair

```
java src/KeyGen.java
```

Saves `keys/public_key.pem` and `keys/private_key.pem`.

If keys already exist, nothing is overwritten. The keys in `keys/` are the pair
used to create the encrypted file, so keep them. To create a new pair elsewhere:

```
java src/KeyGen.java <folder>
```

### 2. Print the SHA-256 hash of a file

```
java src/HashFile.java "files/AMD image file.JPG"
```

Expected output:

```
fa1bed1a61ca81be4d6ecbfe3a75523213a5e399b9db9dd74cfd65303d9c3cc4
```

### 3. Encrypt and decrypt a file

```
java src/FileCrypto.java encrypt <inputFile> <publicKeyPem> <outputFile>
java src/FileCrypto.java decrypt <inputFile> <privateKeyPem> <outputFile>
```

Decrypt the provided encrypted file:

```
java src/FileCrypto.java decrypt "files/AMD image file.JPG.enc" keys/private_key.pem "files/decrypted.JPG"
```

Encrypt the original file again (the output file must not already exist):

```
java src/FileCrypto.java encrypt "files/AMD image file.JPG" keys/public_key.pem "files/encrypted_again.enc"
```

## Verify the result

Compare the hash of the decrypted file with the original:

```
java src/HashFile.java "files/AMD image file.JPG"
java src/HashFile.java "files/decrypted.JPG"
```

Both must print the same hash, which means the decrypted file is identical to the original.

On Windows you can also check with the built-in command:

```
Get-FileHash "files/decrypted.JPG" -Algorithm SHA256
```

## How the encryption works

RSA can only encrypt small data (about 190 bytes with a 2048-bit key), so a
hybrid method is used, the same idea as HTTPS:

1. A new random AES-256 key encrypts the file (AES-GCM).
2. The RSA public key encrypts that AES key (RSA-OAEP with SHA-256).
3. To decrypt, the RSA private key recovers the AES key, which then decrypts the file.

AES-GCM was chosen because it also detects tampering: if the encrypted file is
changed, decryption is refused.

Encrypted file layout:

```
[4 bytes: encrypted AES key length][encrypted AES key: 256 bytes][IV: 12 bytes][encrypted data + 16-byte tag]
```

## Notes

- Existing keys and output files are never overwritten.
- Errors (wrong key, modified file, missing file) print a message and exit with code 1.
- Files are read in 8 KB pieces, so large files do not need to fit in memory.
- The included key pair is a demo key made only for this challenge. In a real system a
  private key would never be shared or stored as a plain file.
- My background is C and C#. I used an AI assistant (Claude) as a tutor to learn Java
  and the cryptography concepts, and to review my code. The code was written, tested
  and debugged by me, step by step, as shown in the commit history.
