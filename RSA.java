import java.security.*;
import java.util.*;
import javax.crypto.*;

public class RSA {
    public static void main (String [] args) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(1024, secureRandom);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

         String originalText = "This is a secret message: RSA edition :)";

        System.out.println("Original Text : "+originalText);

        byte[] encryptedText = encrypt(originalText, publicKey);

        System.out.println("Encrypted Text : "+Base64.getEncoder().encodeToString(encryptedText));

        String decryptedText = decrypt(encryptedText,privateKey);
        System.out.println("Decrypted Text : "+decryptedText);

    }
    public static byte [] encrypt (String originalText, PublicKey pubKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException{

      Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");

      encrypt.init(Cipher.ENCRYPT_MODE, pubKey);

        return encrypt.doFinal(originalText.getBytes());
    }
    public static String decrypt (byte [] encryptedMessage, PrivateKey privKey){
        String decryptedMessage = "";
        return decryptedMessage;
    }
}
