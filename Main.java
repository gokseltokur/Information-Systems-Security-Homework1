import java.util.Base64;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.crypto.spec.IvParameterSpec;

public class Main {
    static Base64.Encoder encoder = Base64.getEncoder();

    public static void main(String[] args) {

        try {
            // Question 1

            // Generate an RSA public-private key pair. KA+ and KA-
            RSA rsa = new RSA();
            System.out.println("Public Key KA(+): \n" + encoder.encodeToString(rsa.getPublicKey().getEncoded()));
            System.out.println("Private Key KA(-): \n" + encoder.encodeToString(rsa.getPrivateKey().getEncoded()));

            // Question 2

            // Generate two symmetric keys: 128 bit K1 and 256 bit K2
            AES aes = new AES();
            System.out.println("128-bit K1 : " + encoder.encodeToString(aes.get128BitKey().getEncoded()));
            System.out.println("256-bit K2 : " + encoder.encodeToString(aes.get256BitKey().getEncoded()));

            // Encypt them with KA+
            byte[] encrypted128BitKey = rsa.encrypt(rsa.getPublicKey(),
                    encoder.encodeToString(aes.get128BitKey().getEncoded()));
            System.out
                    .println("Encrypt K1 with public key:\n" + new String(encoder.encodeToString(encrypted128BitKey)));
            byte[] encrypted256BitKey = rsa.encrypt(rsa.getPublicKey(),
                    encoder.encodeToString(aes.get256BitKey().getEncoded()));
            System.out
                    .println("Encrypt K2 with public key:\n" + new String(encoder.encodeToString(encrypted256BitKey)));

            // Decrypt them with KA-
            byte[] key128Bit = rsa.decrypt(encrypted128BitKey);
            System.out.println("Decrypt K1 with private key:\n" + new String(key128Bit));
            byte[] key256Bit = rsa.decrypt(encrypted256BitKey);
            System.out.println("Decrypt K2 with private key:\n" + new String(key256Bit));

            // Question 3
            // !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!!!!
            // TODO: Change the message
            String message = "A security is a fungible, negotiable financial "
                    + "instrument that holds some type of monetary value. It "
                    + "represents an ownership position in a publicly-traded "
                    + "corporation (via stock), a creditor relationship with a "
                    + "governmental body or a corporation (represented by owning "
                    + "that entity's bond), or rights to ownership as represented " + "by an option";

            System.out.println("m: " + message);

            // Apply SHA256 Hash algorithm (Obtain the message digest,H(m))
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = messageDigest.digest(message.getBytes(StandardCharsets.UTF_8));

            // Byte to hex converter to get the hashed value in hexadecimal
            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (int i = 0; i < encodedhash.length; i++) {
                String hex = Integer.toHexString(0xff & encodedhash[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            System.out.println("H(m): " + hexString.toString());

            // Then encrypt it with KA− (Thus generate a digital signature.)
            byte[] digitalSignature = rsa.signatureEncrypt(hexString.toString());
            System.out.println("KA(-)(H(m)): " + new String(encoder.encodeToString(digitalSignature)));

            // Then verify the digital signature. (Decrypt it with KA+, apply Hash
            // algorithm to the message, compare)
            byte[] decryptedDigitalSignature = rsa.signatureDecrypt(rsa.getPublicKey(), digitalSignature);
            System.out.println("KA(+)(KA(-)(H(m))): " + new String(decryptedDigitalSignature));

            // Question 4
            byte[] content = getFile();
            IvParameterSpec iv = aes.generateIV(16);

            // AES (128 bit key) CBC mode
            // Encrypt the image file.
            byte[] encryptedImageWith128BitKeyCBC = aes.encryptImageFileCBCMode(aes.get128BitKey(), iv, content);
            saveFile(encryptedImageWith128BitKeyCBC, "encryptedWith128BitKeyAESCBC.txt");
            System.out.println("Image encrypted with AES (128 bit key) CBC mode.");

            // Decrypt the file
            byte[] decryptedImageWith128BitKeyCBC = aes.decryptImageFileCBCMode(aes.get128BitKey(), iv,
                    encryptedImageWith128BitKeyCBC);
            saveFile(decryptedImageWith128BitKeyCBC, "./catDecryptedWith128BitKeyAESCBC.jpg");
            System.out.println("Image decrypted with AES (128 bit key) CBC mode.");

            // AES (256 bit key) CBC mode
            // Encrypt the image file.
            byte[] encryptedImageWith256BitKeyCBC = aes.encryptImageFileCBCMode(aes.get256BitKey(), iv, content);
            saveFile(encryptedImageWith256BitKeyCBC, "encryptedWith256BitKeyAESCBC.txt");
            System.out.println("Image encrypted with AES (256 bit key) CBC mode.");

            // Decrypt the file
            byte[] decryptedImageWith256BitKeyCBC = aes.decryptImageFileCBCMode(aes.get256BitKey(), iv,
                    encryptedImageWith256BitKeyCBC);
            saveFile(decryptedImageWith256BitKeyCBC, "./catDecryptedWith256BitKeyAESCBC.jpg");
            System.out.println("Image decrypted with AES (256 bit key) CBC mode.");

            // AES (256 bit key) CTR mode
            // Encrypt the image file.
            byte[] encryptedImageWith256BitKeyCTR = aes.encryptImageFileCTRMode(aes.get256BitKey(), iv, content);
            saveFile(encryptedImageWith256BitKeyCTR, "encryptedWith256BitKeyAESCTR.txt");
            System.out.println("Image encrypted with AES (256 bit key) CTR mode.");

            // Decrypt the file
            byte[] decryptedImageWith256BitKeyCTR = aes.decryptImageFileCTRMode(aes.get256BitKey(), iv,
                    encryptedImageWith256BitKeyCTR);
            saveFile(decryptedImageWith256BitKeyCTR, "./catDecryptedWith256BitKeyAESCTR.jpg");
            System.out.println("Image decrypted with AES (256 bit key) CTR mode.");

            // AES (128 bit key) CBC mode Change Initialization Vector (IV) and show that
            // the corresponding ciphertext chages for the same plaintext

            System.out.println("Message: " + message);

            System.out.println("IV: " + iv);
            IvParameterSpec iv2 = aes.generateIV(16);

            System.out.println("IV2: " + iv2);

            byte[] encryptedWithIv = aes.encryptImageFileCBCMode(aes.get128BitKey(), iv, message.getBytes());
            System.out.println("Message decrypted with AES (128 bit key) CBC mode using IV: \n"
                    + new String(encoder.encodeToString(encryptedWithIv)));

            byte[] encryptedWithIv2 = aes.encryptImageFileCBCMode(aes.get128BitKey(), iv2, message.getBytes());
            System.out.println("Message decrypted with AES (128 bit key) CBC mode using IV2: \n"
                    + new String(encoder.encodeToString(encryptedWithIv2)));

        } catch (Exception e) {
            System.out.println(e);
        }

    }

    public static byte[] getFile() {
        File f = new File("./cat.jpg");
        InputStream is = null;
        try {
            is = new FileInputStream(f);
        } catch (FileNotFoundException e2) {
            e2.printStackTrace();
        }
        byte[] content = null;
        try {
            content = new byte[is.available()];
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        try {
            is.read(content);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return content;
    }

    public static void saveFile(byte[] bytes, String filename) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(bytes);
        fos.close();
    }

}
