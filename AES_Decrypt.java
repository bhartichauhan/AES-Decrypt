import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JTextField;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import java.util.Scanner;

public class AES_Decrypt {
	
	
	 public static void main(String args[]) throws DecoderException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException 
	 {
		 	String result = "";
		 	Scanner sc = new Scanner(System.in);
		 
		 	System.out.println("Enter encrypted text");
			String tobedecrypted = sc.nextLine();
		
			
			System.out.println("Enter password");
			String password1 = sc.nextLine();
			
			
			System.out.println("Enter salt");
			String Salt = sc.nextLine();			

			System.out.println("Enter initvector");
			String initvector = sc.nextLine();
						
		 Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
         
         //Decode string as collection of hex values. Do not use string.getBytes()!             
         byte[] saltBytes = Hex.decodeHex(Salt.toCharArray()); 
         byte[] ivBytes = Hex.decodeHex(initvector.toCharArray());
         
  //Create an AES key derived from the provided password using PBKDF2 with HMAC-SHA1
         SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
         PBEKeySpec keySpec = new PBEKeySpec(password1.toCharArray(), saltBytes, 1000, 256);
         SecretKey tmp = factory.generateSecret(keySpec);
         SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
         
         //create a cipher object using BC
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
         result = decrypt(tobedecrypted, key, ivBytes, cipher);
         System.out.println(result);
                  
	 }
	 public static String decrypt(String tobedecrypted, SecretKey key, byte[] ivBytes, Cipher cipher) throws java.security.InvalidKeyException, java.io.UnsupportedEncodingException, java.security.InvalidAlgorithmParameterException, javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException {
         cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

         //String cipherText = new String(new Base64().decode(inText));
  //byte[] encrypted = cipherText.getBytes();     

         // This replaces the two lines above...
         byte[] et = new Base64().decode(tobedecrypted);
         
         byte[] plaintext = cipher.doFinal(et);
  return(new String(plaintext,"UTF-8"));
}
}	 
