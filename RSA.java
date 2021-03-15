//Ciara O'Donnell and Adriana Buller worked together on this assignment
import java.security.*;
import java.util.*;
import javax.crypto.*;

public class RSA {
    public static void main (String [] args) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(1024, secureRandom);

        KeyPair pair = keyGen.generateKeyPair(); //randomly generate keypair (a public and private key)
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        String originalText = "This is a secret message: RSA edition :)";

        //main method needs to print out the originalText, encryptedText, and decryptedText
        System.out.println("Original Text : "+originalText);

        byte[] encryptedText = encrypt(originalText, publicKey);

        System.out.println("Encrypted Text : "+Base64.getEncoder().encodeToString(encryptedText));

        String decryptedText = decrypt(encryptedText,privateKey);
        System.out.println("Decrypted Text : "+decryptedText);

    }
    public static byte [] encrypt (String originalText, PublicKey pubKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException{
        //get Cipher instance
        Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        //initialize cipher
        encrypt.init(Cipher.ENCRYPT_MODE, pubKey);
        
        //perform encryption
        return encrypt.doFinal(originalText.getBytes());
    }
    
    public static String decrypt (byte [] encryptedMessage, PrivateKey privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        //get Cipher instance
        Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        decrypt.init(Cipher.DECRYPT_MODE, privKey);

        //perform decryption
        byte [] decryptedBytes = decrypt.doFinal(encryptedMessage);

        //convert decrypted bytes into a string
        String decryptedText = new String(decryptedBytes);
        return decryptedText;
    }
}
