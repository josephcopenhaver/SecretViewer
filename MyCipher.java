
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.Mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

public class MyCipher
{
   
   private Cipher cipher=null;
   private byte[] HMACKey=null;
   private Integer cipherMode=null;
   private MyHash myHash = null;
   private Mac mac = null;
   private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
   // valid modes: Cipher.DECRYPT_MODE, Cipher.ENCRYPT_MODE
   
   public static final int DECRYPT_MODE = Cipher.DECRYPT_MODE,
                           ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
   
   public MyCipher() throws NoSuchAlgorithmException
   {
      myHash = new MyHash();
      mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
   }
   
   public boolean init(byte[] credentials) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException
   {
      if (cipherMode == null || credentials == null)
      {
         reset();
         return false;
      }
      else
      {
         cipher=Cipher.getInstance("AES");
         
         byte[] credKey=myHash.getCredKey(credentials);
         HMACKey=myHash.getHMACKeyFromCredKey(credentials, credKey);
         cipher.init(cipherMode, new SecretKeySpec(credKey,0,16,"AES"));
      }
      return true;
   }
   
   public void reset()
   {
      cipher=null;
      HMACKey=null;
   }
   
   public byte[] doFinal(byte[] chunk) throws IllegalBlockSizeException, BadPaddingException
   {
      return cipher.doFinal(chunk);
   }
   
   public byte[] update(byte[] chunk)
   {
      return cipher.update(chunk);
   }
   
   // Can also be used to check if the system is initalized
   public byte[] getHMACKey()
   {
      return HMACKey;
   }
   
   public void setCipherMode(int cipherMode)
   {
      reset();
      this.cipherMode=cipherMode;
   }
   
   public Integer getCipherMode(int cipherMode)
   {
      return cipherMode;
   }
   
   public MyHash getMyHash()
   {
   	  return myHash;
   }
   
   public byte[] getHMAC(byte[] HMACKey, byte[] chunk) throws InvalidKeyException
   {
      mac.reset();
      mac.init(new SecretKeySpec(HMACKey, 0, 16, HMAC_SHA1_ALGORITHM));
      return mac.doFinal(chunk);
   }
   
}
