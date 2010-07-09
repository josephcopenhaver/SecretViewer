
import javax.crypto.Cipher;

import javax.crypto.spec.SecretKeySpec;

class MyCrypto
{
   
   private Cipher cipher=null;
   private byte[] HMAC=null;
   private Integer cipherMode=null;
   // valid modes: Cipher.DECRYPT_MODE, Cipher.ENCRYPT_MODE
   
   public MyCrypto(int cipherMode) throws Exception
   {
      this(cipherMode, null);
   }
   
   public MyCrypto(Integer cipherMode, String credentials) throws Exception
   {
      this.cipherMode=cipherMode;
      if (credentials != null)
         init(credentials);
   }
   
   public boolean init(String credentials) throws Exception
   {
      if (cipherMode == null || credentials == null)
      {
         reset();
         return false;
      }
      else
      {
         cipher=Cipher.getInstance("AES");
         
         String credKey=CryptoHash.getCredKey(credentials);
         System.out.println(credentials);
         System.out.println(credKey);
         HMAC=CryptoHash.getHMACFromCredKey(credentials, credKey);
         System.out.println(new String(HMAC));
         System.out.println(HMAC.length);
         cipher.init(cipherMode, new SecretKeySpec(credKey.getBytes("UTF-8"),0,16,"AES"));
      }
      return true;
   }
   
   public void reset()
   {
      cipher=null;
      HMAC=null;
   }
   
   public byte[] doFinal(byte[] utf8ByteChunk) throws Exception
   {
      return cipher.doFinal(utf8ByteChunk);
   }
   
   public byte[] doFinal(String strChunk) throws Exception
   {
      return cipher.doFinal(strChunk.getBytes("UTF-8"));
   }
   
   // Can also be used to check if the system is initalized
   public byte[] getHMAC()
   {
      return HMAC;
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
   
}
