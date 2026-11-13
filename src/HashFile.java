// AMD Code Challenge
// Application 2:
// Application to generate SHA-256 hash of the attached file. 
// No signing is needed. Just print hash in HEX encoding to standard output.
//
// Dev: Azrin Gan
// Date: 2026-11-13

//include library here
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class HashFile {
    public static void main (String[] args) throws Exception
    {
        // check valid use args
        if (args.length < 1)
        {
            System.out.println("Note: java HashFile.java <filename>");
            return;
        }

        Path filePath = Path.of(args[0]);
        MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");

        try (InputStream inStream = Files.newInputStream(filePath))
        {
            byte[] byteBuffer = new byte[8192];
            int n;
            while ((n = inStream.read(byteBuffer)) != -1)
            {
                msgDigest.update(byteBuffer, 0, n);
            }
        }

        byte[] hash = msgDigest.digest();

        //convert to hex
        StringBuilder hex = new StringBuilder();
        for (byte b : hash)
        {
            hex.append(String.format("%02x", b));
        }

        System.out.println(hex.toString());
    }
}
