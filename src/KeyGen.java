// AMD Code Challenge
// Application 1:
// Application to generate an RSA key pair, key size = 2048 bits
// (Standard Java library can be used to generate all keys and hashes).
//
// Dev: Azrin Gan
// Date: 2026-11-12

// include library here
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class KeyGen {
    public static void main(String[] args) throws Exception
    {
        // generate RSA key pair 2048 bits
        System.out.println("Generate RSA key pair start");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);

        KeyPair keyPair = keyPairGen.generateKeyPair();
        System.out.println("Generate RSA Key Pair done");

        // create location folder to store the keys
        Files.createDirectories(Path.of("keys"));

        // save public key in X.509 format
        System.out.println("Save public key in X.509 format start");
        try (FileOutputStream fileoutputstream = new FileOutputStream("public_key.key"))
        {
            fileoutputstream.write(keyPair.getPublic().getEncoded());
            // convert byte to base64
            String publicKeyBase64 = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());

            System.out.println("Public Key Generated: " + keyPair.getPublic());
            System.out.println("-----BEGIN PUBLIC KEY-----\n" + publicKeyBase64 + "\n-----END PUBLIC KEY-----");
            System.out.println("Save public key done");
        }
        

        // save private key in PKCS format
        System.out.println("Save private key in PKCS format start");
        try (FileOutputStream fileoutputstream = new FileOutputStream("private_key.key"))
        {
            fileoutputstream.write(keyPair.getPrivate().getEncoded());
            // convert byte to base64
            String privateKeyBase64 = Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
            System.out.println("Save private key done");
        }
    }
}