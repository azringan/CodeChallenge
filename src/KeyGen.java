// AMD Code Challenge
// Application 1:
// Application to generate an RSA key pair, key size = 2048 bits
// (Standard Java library can be used to generate all keys and hashes).
//
// Dev: Azrin Gan
// Date: 2026-11-12

// include library here
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class KeyGen
{
    public static void main(String[] args) throws Exception
    {
        // generate RSA key pair 2048 bits
        System.out.println("Generate RSA key pair start");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);

        KeyPair keyPair = keyPairGen.generateKeyPair();
        System.out.println("Generate RSA Key Pair done");

        // check if keys folder exist
        String outputPathDir = (args.length > 0) ? args[0] : "keys";
        Path existKeyPath = Path.of(outputPathDir);
        if (Files.isDirectory(existKeyPath))
        {
            System.out.println("Path exist at: " + existKeyPath.toAbsolutePath());
        }
        else
        {
            // create location folder to store the keys
            Files.createDirectories(existKeyPath);
            System.out.println("Path created at: " + existKeyPath.toAbsolutePath());
        }

        // save public key in X.509 format
        System.out.println("Save public key in X.509 format start");
        // convert keyPair in byte to base64 (64 char per line as per PEM standard)
        String publicKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPublic().getEncoded());
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                              publicKeyBase64 + "\n" +
                              "-----END PUBLIC KEY-----\n";
        Path publicKeyPath = Path.of(outputPathDir, "public_key.pem");
        Files.writeString(publicKeyPath, publicKeyPem);
        System.out.println("Public key saved to: " + publicKeyPath.toAbsolutePath());

        // save private key in PKCS format
        System.out.println("Save private key in PKCS format start");
        // convert keyPair in byte to base64 (64 char per line as per PEM standard)
        String privateKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded());
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                              privateKeyBase64 + "\n" +
                              "-----END PRIVATE KEY-----\n";
        Path privateKeyPath = Path.of(outputPathDir, "private_key.pem");
        Files.writeString(privateKeyPath, privateKeyPem);
        System.out.println("Private key saved to: " + privateKeyPath.toAbsolutePath());
    }
}
