import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

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
}
