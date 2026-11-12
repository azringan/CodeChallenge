// AMD Code Challenge
// Application 1:
// Application to generate an RSA key pair, key size = 2048 bits
// (Standard Java library can be used to generate all keys and hashes).
//
// Dev: Azrin Gan
// Date: 2026-11-12

// include library here
// import java.io.File;
// import java.io.FileOutputStream;
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

        // create location folder to store the keys
        Files.createDirectories(Path.of("keys"));

        // save public key in X.509 format
        System.out.println("Save public key in X.509 format start");
//#region IncorrectPublicKey
        // this way of writing creats a public_key.key directly into current working file, and key is in byte which unreadable format. need DER format.
        // try (FileOutputStream fileoutputstream = new FileOutputStream("public_key.key"))
        // {
        //     fileoutputstream.write(keyPair.getPublic().getEncoded());
        //     // convert byte to base64
        //     String publicKeyBase64 = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());

        //     System.out.println("Public Key Generated: " + keyPair.getPublic());
        //     System.out.println("-----BEGIN PUBLIC KEY-----\n" + publicKeyBase64 + "\n-----END PUBLIC KEY-----");
        //     System.out.println("Save public key done");
        // }
        //
//#endregion
        // convert keyPair in byte to base64 (64 char per line as per PEM standard)
        String publicKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPublic().getEncoded());
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                              publicKeyBase64 + "\n" +
                              "-----END PUBLIC KEY-----\n";
        Path publicKeyPath = Path.of("keys","public_key.pem");
        Files.writeString(publicKeyPath, publicKeyPem);
        System.out.println("Public key saved to: " + publicKeyPath.toAbsolutePath());

        // save private key in PKCS format
        System.out.println("Save private key in PKCS format start");
//#region IncorrectPrivateKey
        // this way of writing creats a private_key.key directly into current working file, and key is in byte which unreadable format. need DER format.
        // try (FileOutputStream fileoutputstream = new FileOutputStream("private_key.key"))
        // {
        //     fileoutputstream.write(keyPair.getPrivate().getEncoded());
        //     // convert byte to base64
        //     String privatekeybase64 = Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
        //     System.out.println("Save private key done");
        // }
//#endregion
        String privateKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded());
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                              privateKeyBase64 + "\n" +
                              "-----END PRIVATE KEY-----\n";
        Path privateKeyPath = Path.of("keys","private_key.pem");
        Files.writeString(privateKeyPath, privateKeyPem);
        System.out.println("Private key saved to: " + privateKeyPath.toAbsolutePath());
    }
}
