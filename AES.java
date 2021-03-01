import java.security.NoSuchAlgorithmException;

import javax.crypto.*;

public class AES {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 

    }

    public static byte[] encrypt(){
        byte [] encryptedText = new byte [0]; //0 is just a toy length for now
        return encryptedText;
    }

    public static byte[] decrypt(){
        byte [] decryptedText = new byte [0]; //0 is just a toy length for now
        return decryptedText;
    }
}
