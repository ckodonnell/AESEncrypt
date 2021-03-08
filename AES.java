//Ciara O'Donnell and Adriana Buller worked together on this assignment
import java.security.NoSuchAlgorithmException;

import java.security.Key;

import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.*;

public class AES {
    static String originalText = "This is a secret message :)";

    public static void main(String[] args) throws Exception, NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 128;
        keyGen.init(keyBitSize, secureRandom); //want to make sure key is given to us in byte vector

        //make the key
      SecretKey key = keyGen.generateKey();


        //make an initial vector
        byte[] initVect = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(initVect);

        //main method needs to print out the originalText, encryptedText, and decryptedText so we can tell if this works

        System.out.println("Original Text : "+originalText);

        byte[] encryptedText = encrypt(originalText.getBytes(), key, initVect);
        System.out.println("Encrypted Text : "+Base64.getEncoder().encodeToString(encryptedText)); //we need to turn the encrypted text from byte[] to a string

        String decryptedText = decrypt(encryptedText,key,initVect);
        System.out.println("Decrypted Text : "+decryptedText);
    }

    public static byte[] encrypt(byte[] originalText, SecretKey key, byte[] initVect) throws Exception // we need all this stuff to be able to encrypt something
    {
      //we need to tell everything that we are doing AES/get it into the format to be able to do the initialization

      //get Cipher instance
      Cipher encrypt =
      Cipher.getInstance("AES/CBC/PKCS5Padding");


      //Encode the key for AES operations
      SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");//SecretKeySpec requires a byte array, so we have to do key.getEncoded()

      //create IvParameterSpec
      IvParameterSpec ivSpec = new IvParameterSpec(initVect);

      //initialize encrypter
      encrypt.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

      //perform encryption
      byte [] encryptedText = encrypt.doFinal(originalText);

      return encryptedText;
    }

    public static String decrypt(byte[] encryptedText, SecretKey key, byte[] initVect)
            throws Exception // we need all this stuff to be able to decrypt a
                                                                   // message
    { 
       //get Cipher instance
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");

        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        //create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(initVect);

        //initialize decrypter with key and iv
        decrypt.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //perform the decryption
        byte[] decryptedBytes = decrypt.doFinal(encryptedText);
         
        //convery decrypted bytes into String format
        String decryptedText = new String(decryptedBytes);

        return decryptedText;
    }
}
