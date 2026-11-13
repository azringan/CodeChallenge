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

public class HashFile 
{
    // declare const var
    private static final int BUFFER_SIZE = 8192; // read a file with 8 KB size 

    public static void main(String[] args) throws Exception
    {
        // check valid use args
        if (args.length < 1)
        {
            System.err.println("Usage: java src/HashFile.java <file>");
            System.exit(1);
        }

        // check file exist
        Path filePath = Path.of(args[0]);
        if (!Files.isRegularFile(filePath))
        {
            System.err.println("File not found: " + filePath.toAbsolutePath());
            System.exit(1);
        }

        byte[] hash = computeSha256(filePath);
        System.out.println(HexFormat.of().formatHex(hash)); // hash in small letters. use HexFormat.of().withUpperCase() if need in capital letters
    }

    // Compute the file into SHA-256
    // Read in byte chunks so that large file no need to fit into memory
    private static byte[] computeSha256(Path file) throws Exception
    {
        MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");

        try (InputStream inStream = Files.newInputStream(file))
        {
            byte[] byteBuffer = new byte[BUFFER_SIZE];
            int nBytesRead;
            while ((nBytesRead = inStream.read(byteBuffer)) != -1)
            {
                msgDigest.update(byteBuffer, 0, nBytesRead);
            }
        }

        return msgDigest.digest();
    }
}
