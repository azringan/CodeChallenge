// AMD Code Challenge
// Application 3:
// Application that will encrypt and decrypt the file using the RSA key pair generated.
//
// Dev: Azrin Gan
// Date: 2026-11-14

//include library here
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.*;

public class FileCrypto {
    
    private static final String RSA_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_TRANSFORM = "AES/CBC/PKCS5padding";

    public static void main(String[] args) throws Exception
    {
        if (args.length != 4 || !(args[0].equals("encrypt")) || !(args[0].equals("decrypt")))
        {
            System.out.println("Usage:");
            System.out.println("java src/FileCrypto.java encrypt <inputFile> <publicKeyPem> <outputFile>");
            System.out.println("java src/FileCrypto.java decrypt <inputFile> <privateKeyPem> <outputFile>");
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
        
        // check args[2]
        try 
        {
            if (mode.equals("encrypt")) {
                PublicKey publicKey = loadPublicKey(keyPath);
                encryptFile(inputFilePath, outputFilePath, publicKey);
                System.out.println("Encrypted: " + outputFilePath);
            } else if (mode.equals("decrypt")) {
                PrivateKey privateKey = loadPrivateKey(keyPath);
                decryptFile(inputFilePath, outputFilePath, privateKey);
                System.out.println("Decrypted: " + outputFilePath);
            }
        }
        catch (BadPaddingException e)
        {
            System.err.println("Decryption failed: wrong private key for this file.");
            System.exit(1);
        }
        catch (IllegalArgumentException e)
        {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    private static PublicKey loadPublicKey(Path path) throws Exception
    {
        byte[] der = convertPemToDer(Files.readString(path), "PUBLIC KEY");

        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private  static PrivateKey loadPrivateKey(Path path) throws Exception
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
            throw new IllegalArgumentException("Not a PEM " + type + "file.");
        }

        String keyBase64 = pem.substring(start + begin.length(), stop);
        return Base64.getMimeDecoder().decode(keyBase64);
    }

    private static void encryptFile(Path inputPath, Path outputPath, PublicKey publicKey) throws Exception
    {
        //generate random AES key
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesSecretKey = aesKeyGen.generateKey();

        //encrypt AES key with RSA
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAeskey = rsaCipher.doFinal(aesSecretKey.getEncoded());

        //ecnrypt file
        byte[] IV = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(IV);

        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesSecretKey, new IvParameterSpec(IV));

        try (FileOutputStream fileOutputStream = new  FileOutputStream(outputPath.toFile());
             DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);
             FileInputStream fileInputStream = new FileInputStream(inputPath.toFile());
             CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, aesCipher))
        {
            //write: [4 bytes AES key length][encrypted AES key][16 bytes IV][encrypted data]
            dataOutputStream.writeInt(encryptedAeskey.length);
            dataOutputStream.write(encryptedAeskey);
            dataOutputStream.write(IV);

            //stream encrypted data
            byte[] byteBuffer = new byte[8192];
            int n;
            while ((n = cipherInputStream.read(byteBuffer)) != -1)
            {
                dataOutputStream.write(byteBuffer, 0, n);
            }
            cipherInputStream.close();
        }
    }

    private static void decryptFile(Path inpuPath, Path outpuPath, PrivateKey privateKey) throws Exception
    {
        try (FileInputStream fileInputStream = new FileInputStream(inpuPath.toFile());
             DataInputStream dataInputStream = new DataInputStream(fileInputStream);
             FileOutputStream fileOutputStream = new FileOutputStream(outpuPath.toFile()))
        {
            //read encrypted AES
            int nKeyLength = dataInputStream.readInt();
            byte[] byteEncryptedAeskey = new byte[nKeyLength];
            dataInputStream.readFully(byteEncryptedAeskey);

            //read IV
            byte[] IV = new byte[16];
            dataInputStream.readFully(IV);

            //decrypt AES key with RSA
            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORM);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] byteAesKey = rsaCipher.doFinal(byteEncryptedAeskey);
            SecretKey secretAesKey = new SecretKeySpec(byteAesKey, "AES");

            //decrypt file with AES
            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORM);
            aesCipher.init(Cipher.DECRYPT_MODE, secretAesKey, new IvParameterSpec(IV));

            CipherInputStream cipherInputStream = new CipherInputStream(dataInputStream, aesCipher);
            byte[] byteBuffer = new byte[8192];
            int n;
            while ((n = cipherInputStream.read(byteBuffer)) != -1)
            {
                fileOutputStream.write(byteBuffer, 0, n);
            }
            cipherInputStream.close();
        }
    }
}
