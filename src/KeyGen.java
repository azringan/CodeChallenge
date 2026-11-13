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
    // declare const var
    private static final int KEY_SIZE = 2048;
    private static final String DEFAULT_KEY_DIR = "keys";
    private static final String PUBLIC_KEY_FILE = "public_key.pem"; 
    private static final String PRIVATE_KEY_FILE = "private_key.pem"; 

    public static void main(String[] args) throws Exception
    {
        // check if keys exist
        String outputPathDir = (args.length > 0) ? args[0] : DEFAULT_KEY_DIR;
        Path publicKeyPath = Path.of(outputPathDir, PUBLIC_KEY_FILE);
        Path privateKeyPath = Path.of(outputPathDir, PRIVATE_KEY_FILE);

        if (isAnyKeyExist(publicKeyPath, privateKeyPath))
        {
            return;
        }

        // generate RSA key pair 2048 bits
        checkExistenceDirectory(Path.of(outputPathDir));
        KeyPair keyPair = generateNewKeyPair();

        // save keys into PEM files
        savePemKey(publicKeyPath,  "PUBLIC KEY",  keyPair.getPublic().getEncoded());
        savePemKey(privateKeyPath, "PRIVATE KEY", keyPair.getPrivate().getEncoded());
    }

    private static boolean isAnyKeyExist(Path publicKeyPath, Path privateKeyPath)
    {
        boolean isPublicKeyExist = Files.exists(publicKeyPath);
        boolean isPrivateKeyExist = Files.exists(privateKeyPath);

        if (isPublicKeyExist || isPrivateKeyExist)
        {
            System.out.println("public_key status: " + (isPublicKeyExist ? "found" : "missing"));
            System.out.println("private_key status: " + (isPrivateKeyExist ? "found" : "missing"));

            // check any missing key
            if (isPublicKeyExist && isPrivateKeyExist)
            {
                System.out.println("Both keys found. No need to generate new keys.");
                System.out.println("Please decrypt the files first before deleting any existing key. Once decrypted and keys are deleted, proceed to generate a new pair of keys.");
            }
            else if (isPrivateKeyExist)
            {
                System.out.println("Only private key found. Public key can be derived from it.");
                System.out.println("Please decrypt the files first before deleting any existing key. Once decrypted and keys are deleted, proceed to generate a new pair of keys.");
            }
            else
            {
                System.out.println("WARNING: Only public key found! Private key is currently missing or has been deleted.");
                System.out.println("Files encrypted with this public key can no longer be decrypted.");
                System.out.println("Please remove public key or choose another folder to generate a new pair.");
            }

            return true;
        }

        return false;
    }

    // Create new pair of keys
    private static KeyPair generateNewKeyPair() throws Exception
    {
        // generate RSA key pair 2048 bits
        System.out.println("Generate RSA key pair start");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(KEY_SIZE);

        KeyPair newKeyPair = keyPairGen.generateKeyPair();
        System.out.println("Generate RSA Key Pair done");

        return newKeyPair;
    }

    // Check if the key folder directory already existed.
    // Create new one if not exist.
    private static void checkExistenceDirectory(Path dirKeyPath) throws Exception
    {
        if (Files.isDirectory(dirKeyPath))
        {
            System.out.println("Path exist at: " + dirKeyPath.toAbsolutePath());
        }
        else
        {
            Files.createDirectories(dirKeyPath);
            System.out.println("Path created at: " + dirKeyPath.toAbsolutePath());
        }
    }

    // Convert DER key bytes into Base64 text format following PEM standard (64 chars per line)
    // Public key is saved in X.509 format. Private key is saved in PKCS format.
    private static void savePemKey(Path path, String type, byte[] der) throws Exception
    {
        String keyBase64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);

        String keyPem = "-----BEGIN " + type + "-----\n" +
                        keyBase64 + "\n" +
                        "-----END " + type + "-----\n";

        Files.writeString(path, keyPem);
        System.out.println(type + " saved to: " + path.toAbsolutePath());
    }
}
