// AMD Code Challenge
// Application 3:
// Application that will encrypt and decrypt the file using the RSA key pair generated.
//
// Dev: Azrin Gan
// Date: 2026-11-14

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.*;

public class FileCrypto
{
    private static final String RSA_TRANSFORM = "RSA/ECB/OAEPPadding";
    private static final String AES_TRANSFORM = "AES/GCM/NoPadding";
    private static final int BUFFER_SIZE = 8192;
    private static final int MAX_ENCRYPTED_KEY_LENGTH = 1024;   // bytes; RSA-2048 gives 256
    private static final int AES_KEY_BITS = 256;
    private static final int IV_BYTES = 12;                     // CBC use 16. GCM use 12, standard nonce(number used once) size
    private static final int GCM_AUTH_TAG_BITS = 128;           // 16 byte authentication tag
    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    public static void main(String[] args) throws Exception
    {
        if (args.length != 4 || !(args[0].equals("encrypt") || args[0].equals("decrypt")))
        {
            System.err.println("Usage:");
            System.err.println("java src/FileCrypto.java encrypt <inputFile> <publicKeyPem> <outputFile>");
            System.err.println("java src/FileCrypto.java decrypt <inputFile> <privateKeyPem> <outputFile>");
            System.exit(1);
        }

        String mode = args[0];
        Path inputFilePath = Path.of(args[1]);
        Path keyPath = Path.of(args[2]);
        Path outputFilePath = Path.of(args[3]);

        //validate each path
        if (!Files.isRegularFile(inputFilePath))
        {
            System.err.println("Input file not found: " + inputFilePath.toAbsolutePath());
            System.exit(1);
        }
        if (!Files.isRegularFile(keyPath))
        {
            System.err.println("Key file not found: " + keyPath.toAbsolutePath());
            System.exit(1);
        }
        if (Files.exists(outputFilePath))
        {
            System.err.println("Output file already exists, not overwriting: " + outputFilePath.toAbsolutePath());
            System.exit(1);
        }
        
        // check mode to encrypt/decrypt
        try 
        {
            if (mode.equals("encrypt")) 
            {
                PublicKey publicKey = loadPublicKey(keyPath);
                encryptFile(inputFilePath, outputFilePath, publicKey);
                System.out.println("Encrypted: " + outputFilePath.toAbsolutePath());
            }
            else if (mode.equals("decrypt"))
            {
                PrivateKey privateKey = loadPrivateKey(keyPath);
                decryptFile(inputFilePath, outputFilePath, privateKey);
                System.out.println("Decrypted: " + outputFilePath.toAbsolutePath());
            }
        }
        catch (BadPaddingException e)
        {
            Files.deleteIfExists(outputFilePath);
            System.err.println("Decryption failed: wrong private key for this file.");
            System.exit(1);
        }
        catch (IllegalArgumentException e)
        {
            Files.deleteIfExists(outputFilePath);
            System.err.println(e.getMessage());
            System.exit(1);
        }
        catch (InvalidKeySpecException e)
        {
            Files.deleteIfExists(outputFilePath);
            System.err.println("Invalid key file: wrong key type or damaged PEM.");
            System.exit(1);
        }
        catch (IOException e)
        {
            Files.deleteIfExists(outputFilePath);
            System.err.println("Decryption failed: file is corrupted or was modified.");
            System.exit(1);
        }
    }

    private static PublicKey loadPublicKey(Path path) throws Exception
    {
        byte[] der = convertPemToDer(Files.readString(path), "PUBLIC KEY");

        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static PrivateKey loadPrivateKey(Path path) throws Exception
    {
        byte[] der = convertPemToDer(Files.readString(path), "PRIVATE KEY");

        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static byte[] convertPemToDer(String pem, String type)
    {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";

        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);

        if (start < 0 || stop < 0)
        {
            throw new IllegalArgumentException("Not a PEM " + type + " file.");
        }

        String keyBase64 = pem.substring(start + begin.length(), stop);
        return Base64.getMimeDecoder().decode(keyBase64);
    }

    // Encrypt file
    // Generate random AES key and encrypt the key with RSA
    // Generate Initialization Vector (IV) in the AES
    // Write in [4 bytes AES key length][encrypted AES key][16 bytes IV][encrypted data + 16-byte auth tag]
    private static void encryptFile(Path inputPath, Path outputPath, PublicKey publicKey) throws Exception
    {
        //generate random AES key
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(AES_KEY_BITS);
        SecretKey aesSecretKey = aesKeyGen.generateKey();

        //encrypt AES key with RSA
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesSecretKey.getEncoded());

        //generate random initialization vector (IV) in AES
        byte[] IV = new byte[IV_BYTES];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(IV);

        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesSecretKey, new GCMParameterSpec(GCM_AUTH_TAG_BITS, IV));

        //open I/O files, write header to output, stream read input as AES encrypted
        try (FileOutputStream fileOutputStream = new FileOutputStream(outputPath.toFile());
             DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);
             FileInputStream fileInputStream = new FileInputStream(inputPath.toFile());
             CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, aesCipher))
        {
            //write: [4 bytes AES key length][encrypted AES key][16 bytes IV][encrypted data + 16-byte auth tag]
            //write header
            dataOutputStream.writeInt(encryptedAesKey.length);
            dataOutputStream.write(encryptedAesKey);
            dataOutputStream.write(IV);

            //stream encrypted data after the header, with 8KB at a time
            byte[] byteBuffer = new byte[BUFFER_SIZE];
            int nBytesRead;
            while ((nBytesRead = cipherInputStream.read(byteBuffer)) != -1)
            {
                dataOutputStream.write(byteBuffer, 0, nBytesRead);
            }
        }
    }

    // Decrypt file
    // Read encrypted AES key and check if it has the correct length.
    // Decrypt the AES key with RSA
    // Decrypt the file with AES
    private static void decryptFile(Path inputPath, Path outputPath, PrivateKey privateKey) throws Exception
    {
        try (FileInputStream fileInputStream = new FileInputStream(inputPath.toFile());
             DataInputStream dataInputStream = new DataInputStream(fileInputStream))
        {
            //read encrypted AES key length
            int nKeyLength = dataInputStream.readInt();
            //check key length is correct
            if (nKeyLength <= 0 || nKeyLength > MAX_ENCRYPTED_KEY_LENGTH)
            {
                throw new IllegalArgumentException("Not a file encrypted by this tool.");
            }

            byte[] byteEncryptedAesKey = new byte[nKeyLength];
            dataInputStream.readFully(byteEncryptedAesKey);

            //read IV
            byte[] IV = new byte[IV_BYTES];
            dataInputStream.readFully(IV);

            //decrypt AES key with RSA
            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORM);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256);
            byte[] byteAesKey = rsaCipher.doFinal(byteEncryptedAesKey);
            SecretKey secretAesKey = new SecretKeySpec(byteAesKey, "AES");

            //decrypt file with AES
            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORM);
            aesCipher.init(Cipher.DECRYPT_MODE, secretAesKey, new GCMParameterSpec(GCM_AUTH_TAG_BITS, IV));

            //only create the output file after checking header and key are good
            try (CipherInputStream cipherInputStream = new CipherInputStream(dataInputStream, aesCipher);
                 FileOutputStream fileOutputStream = new FileOutputStream(outputPath.toFile()))
            {
                byte[] byteBuffer = new byte[BUFFER_SIZE];
                int nBytesRead;
                while ((nBytesRead = cipherInputStream.read(byteBuffer)) != -1)
                {
                    fileOutputStream.write(byteBuffer, 0, nBytesRead);
                }
            }
        }
    }
}
