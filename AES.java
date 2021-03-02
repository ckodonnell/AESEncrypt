import java.security.NoSuchAlgorithmException;

import java.security.SecureRandom;
import javax.crypto.*;

import java.util.*;

public class AES {
    static String originalText = "This is a secret message :)";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); //want to make sure key is given to us in byte vector

        //make the key
        SecretKey key = KeyGenerator.generateKey();


        //make an initial vector
        byte[] initVect = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(initVect);

        //main method needs to print out the originalText, encryptedText, and decryptedText so we can tell if this works

        System.out.println("Original Text : "+originalText);

        byte[] encryptedText = encrypt(plainText.getBytes(), key, initVect);
        System.out.println("Encrypted Text : "+Base64.getEncoder().encodeToString(encryptedText)); //we need to turn the encrypted text from byte[] to a string

        String decryptedText = decrypt(encryptedText,key,initVect);
        System.out.println("Decrypted Text : "+decryptedText);
    }

    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] initVect)// we need all this stuff to be able to encrypt something
    {
        byte [] encryptedText = new byte [0]; //0 is just a toy length for now
        return encryptedText;
    }

    public static byte[] decrypt(byte[] encryptedText, SecretKey key, byte[] initVect)//we need all this stuff to be able to decrypt a message
    {
        byte [] decryptedText = new byte [0]; //0 is just a toy length for now
        return decryptedText;
    }
}
