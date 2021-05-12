import java.security.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;

public class question1 {

    Base64.Encoder encoder = Base64.getEncoder();

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException{
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();


        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
    }
    
}
