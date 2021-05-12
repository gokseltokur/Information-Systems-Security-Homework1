import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Security_hw {
	static Cipher ecipher;
	static Cipher dcipher;
	static byte[] buf = new byte[1024];
	static Base64.Encoder enc = Base64.getEncoder();
    private static final String UTF_8 = null;
    private static final byte[] initialization_vector = { 22, 33, 11, 44, 55, 99, 66, 77 };

	public static void main (String args[]){
        try {
            /// Question 1       	
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");     
            kpg.initialize(1024);   
            
            KeyPair kp = kpg.generateKeyPair();   
            PrivateKey prk = kp.getPrivate();   
            PublicKey puk = kp.getPublic();    
            
            System.out.println("--------RSA Public/Private Key Pair-------- ");
            System.out.println("------------------------------------------- \n");
            System.out.println("Public Key KA(+): \n" + enc.encodeToString(puk.getEncoded()) + "\n");
            System.out.println("Private Key KA(-): \n" + enc.encodeToString(prk.getEncoded()) + "\n\n");
            
            /// Question 2
            System.out.println("128 bit symmetric key K1:");
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128);
            Key k128 = generator.generateKey();
            System.out.println("K1: " + new String(enc.encodeToString(k128.getEncoded())) + "\n");
            
            System.out.println("256 bit symmetric key K2:");
            KeyGenerator generator2 = KeyGenerator.getInstance("AES");
            generator.init(256);
            Key k256 = generator.generateKey();
            System.out.println("K2: " + new String(enc.encodeToString(k256.getEncoded())) + "\n");
            
            System.out.println("Encryption K1 with public key:\n");
            byte [] encrypted128 = encrypt(puk, new String(enc.encodeToString(k128.getEncoded())));     
            System.out.println(new String(enc.encodeToString(encrypted128))); 
            System.out.println("\nDecryption K1 with private key:\n");
            byte[] decrypted128 = decrypt(prk, encrypted128);                                 
            System.out.println(new String(decrypted128));     // This is a secret message
            
            
            System.out.println("\n\nEncryption K2 with public key:\n");
            byte [] encrypted256 = encrypt(puk, new String(enc.encodeToString(k128.getEncoded())));     
            System.out.println(new String(enc.encodeToString(encrypted256))); 
            System.out.println("\nDecryption K2 with private key:\n");
            byte[] decrypted256 = decrypt(prk, encrypted256);                                 
            System.out.println(new String(decrypted256));     // This is a secret message
            
            
            /// Question 3
            
            String message = "A security is a fungible, negotiable financial "
            		+ "instrument that holds some type of monetary value. It "
            		+ "represents an ownership position in a publicly-traded "
            		+ "corporation (via stock), a creditor relationship with a "
            		+ "governmental body or a corporation (represented by owning "
            		+ "that entity's bond), or rights to ownership as represented "
            		+ "by an option";
            
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashInBytes = md.digest(message.getBytes(StandardCharsets.UTF_8));

    		// bytes to hex
            StringBuilder sb = new StringBuilder();
            for (byte b : hashInBytes) {
                sb.append(String.format("%02x", b));
            }
            System.out.println("\nH(m): " + sb.toString());

            byte [] encHm = signEncrypt(prk, sb.toString());     
            System.out.println("KA(-)(H(m)): "+new String(enc.encodeToString(encHm)));
            byte[] decHm = signDecrypt(puk, encHm);                                 
            System.out.println("KA(+)(KA(-)(H(m))): " +new String(decHm));  
      
            /// Question 4
  	        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
  	    	sha256_HMAC.init(k128);
  	    	System.out.println("\n\nHMAC m using K1 and SHA256: " +enc.encodeToString(sha256_HMAC.doFinal(message.getBytes("UTF-8")))+"\n");
  	    	
  	    	 /// Question 5
  	    	 
   			byte[] iv = new byte[16];
   			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
  	    	 

  	    	 
  	    	 //AES 128 CBC
  			try{
  				ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
  				dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
  				
  				// CBC requires an initialization vector
  				ecipher.init(Cipher.ENCRYPT_MODE, k128, paramSpec);
  				dcipher.init(Cipher.DECRYPT_MODE, k128, paramSpec);
  				
  				// Encrypt
  				long startTime3=System.nanoTime();
  				encryptAES(new FileInputStream("file.txt"),new FileOutputStream("encK1.txt"));
  				long endTime3=System.nanoTime();
  	   		    long time3=endTime3-startTime3;
  	   		    System.out.println("AES128 encryption took "+time3 +" nanosecond");
  				// Decrypt
  	   		    long startTime4=System.nanoTime();
  				decryptAES(new FileInputStream("encK1.txt"),new FileOutputStream("decK1.txt"));
  				long endTime4=System.nanoTime();
  	   		    long time4=endTime4-startTime4;
  	   		    //System.out.println("AES128 decryption took "+time4 +" nanosecond");
  			}
  			catch (Exception e){
  				e.printStackTrace();
  			}
  	    	 
  			
            //AES 256 CBC
			try{
  				
  				ecipher.init(Cipher.ENCRYPT_MODE, k256, paramSpec);
  				dcipher.init(Cipher.DECRYPT_MODE, k256, paramSpec);
  				
  				// Encrypt
  				long startTime5=System.nanoTime();
  				encryptAES(new FileInputStream("file.txt"),new FileOutputStream("encK2.txt"));
  				long endTime5=System.nanoTime();
  	   		    long time5=endTime5-startTime5;
  	   		    System.out.println("AES256 encryption took "+time5 +" nanosecond");
  				// Decrypt
  				decryptAES(new FileInputStream("encK2.txt"),new FileOutputStream("decK2.txt"));
  			}
  			catch (Exception e){
  				e.printStackTrace();
  			}
  		
			//DES CBC
			try {  
				
				SecretKey secret_key = KeyGenerator.getInstance("DES")
						.generateKey();
				
				AlgorithmParameterSpec alogrithm_specs = new IvParameterSpec(
						initialization_vector);

				ecipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
				ecipher.init(Cipher.ENCRYPT_MODE, secret_key, alogrithm_specs);

				dcipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
				dcipher.init(Cipher.DECRYPT_MODE, secret_key, alogrithm_specs);

				long startTime6=System.nanoTime();
				encryptDES(new FileInputStream("file.txt"), new FileOutputStream("encDES.txt"));
  				long endTime6=System.nanoTime();
  	   		    long time6=endTime6-startTime6;
  	   		    System.out.println("DES encryption took "+time6 +" nanosecond");
				
				decryptDES(new FileInputStream("encDES.txt"), new FileOutputStream("decDES.txt"));

			} catch (Exception e) {
				e.printStackTrace();
			}
			
			         
        } catch (Exception e) {
            System.out.println(e);
        } 
        
    }
    
	    public static byte[] decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");  
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        return cipher.doFinal(encrypted);
	    }
	    public static byte[] encrypt(PublicKey publicKey, String message) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");  
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
	        return cipher.doFinal(message.getBytes());  
	    }
	    
	    public static byte[] signDecrypt(PublicKey publicKey, byte [] encrypted) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");  
	        cipher.init(Cipher.DECRYPT_MODE, publicKey);
	        return cipher.doFinal(encrypted);
	    }
	    
	    public static byte[] signEncrypt(PrivateKey privateKey, String message) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");  
	        cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
	        return cipher.doFinal(message.getBytes());  
	    }
	    
	    public static void encryptAES(InputStream in, OutputStream out){
			try{
				out = new CipherOutputStream(out, ecipher);
				int numRead = 0;
				while ((numRead = in.read(buf)) >= 0){
					out.write(buf, 0, numRead);
				}
				out.close();
			}
			catch (java.io.IOException e){
			}
		}
		
		public static void decryptAES(InputStream in, OutputStream out){
			try{
				in = new CipherInputStream(in, dcipher);
				int numRead = 0;
				while ((numRead = in.read(buf)) >= 0){
					out.write(buf, 0, numRead);
				}
				out.close();
			}
			catch (java.io.IOException e)
			{
			}
		}
	  
		private static void encryptDES(InputStream input, OutputStream output)
				throws IOException{
			output = new CipherOutputStream(output, ecipher);
			writeBytes(input, output);
		}

		private static void decryptDES(InputStream input, OutputStream output)
				throws IOException {
			input = new CipherInputStream(input, dcipher);
			writeBytes(input, output);
		}

		private static void writeBytes(InputStream input, OutputStream output)
				throws IOException {
			byte[] writeBuffer = new byte[512];
			int readBytes = 0;
			while ((readBytes = input.read(writeBuffer)) >= 0) {
				output.write(writeBuffer, 0, readBytes);
			}

			output.close();
			input.close();
		}
		
}