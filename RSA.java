import java.security.*;
import java.util.*;
import javax.crypto.*;

public class RSA {
    public static void main (String [] args) throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(1024, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        static String originalText = "This is a secret message: RSA edition :)";

        System.out.println("Original Text : "+originalText);

        byte[] encryptedText = encrypt(originalText, publicKey);

        System.out.println("Encrypted Text : "+Base64.getEncoder().encodeToString(encryptedText));

        String decryptedText = decrypt(encryptedText,privatKey);
        System.out.println("Decrypted Text : "+decryptedText);

    }
    public byte [] encrypt (String originalText, PublicKey public){

      Cipher cipher = Cipher.getInstance("RSA");

      cipher.init(Cipher.ENCRYPT_MODE, public)

        return cipher.doFinal(plainText.getBytes());
    }
    public String decrypt (byte [] encryptedMessage, PrivateKey private){
        String decryptedMessage = "";
        return decryptedMessage;
    }
}
