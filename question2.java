import javax.crypto.*;
import java.security.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;

public class question2 {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        Key k1 = keyGenerator.generateKey();

        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("AES");
        keyGenerator2.init(256);
        Key k2 = keyGenerator.generateKey();

        System.out.println("128-bit k1 : " + Base64.getEncoder().encodeToString(k1.getEncoded()) + "\n" + "256-bit k2 : " + Base64.getEncoder().encodeToString(k2.getEncoded()));

    }
}
