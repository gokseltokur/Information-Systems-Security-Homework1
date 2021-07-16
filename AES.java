//
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AES {
    private Key k1;
    private Key k2;

    // Generate 128 bit and 256 bit symmetric keyt
    public AES() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        this.k1 = keyGenerator.generateKey();

        keyGenerator.init(256);
        this.k2 = keyGenerator.generateKey();
    }

    public Key get128BitKey() {
        return k1;
    }

    public Key get256BitKey() {
        return k2;
    }

    public IvParameterSpec generateIV(int ivSize) {
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        return ivParameterSpec;
    }

    // Encrypt image with AES CBC mode
    public byte[] encryptImageFileCBCMode(Key key, IvParameterSpec iv, byte[] content) {
        Cipher cipher;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            encrypted = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    // Decrypt image with AES CBC mode
    public byte[] decryptImageFileCBCMode(Key key, IvParameterSpec iv, byte[] decryptedContent) {
        Cipher cipher;
        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            decrypted = cipher.doFinal(decryptedContent);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }

    // Encrypt image with AES CTR mode
    public byte[] encryptImageFileCTRMode(Key key, IvParameterSpec iv, byte[] content) {
        Cipher cipher;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            encrypted = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    // Decrypt image with AES CTR mode
    public byte[] decryptImageFileCTRMode(Key key, IvParameterSpec iv, byte[] decryptedContent) {
        Cipher cipher;
        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            decrypted = cipher.doFinal(decryptedContent);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }
}
