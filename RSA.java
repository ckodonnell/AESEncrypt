import java.security.*;
import java.util.*;

public class RSA {
    public static void main (String [] args) throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(1024, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();

    }
    public byte [] encrypt (byte [] plainText){
        return plainText;
    }
    public String decrypt (byte [] encryptedMessage){
        String decryptedMessage = ""; 
        return decryptedMessage;
    }
}
