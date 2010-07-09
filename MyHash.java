
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MyHash
{
	
	private MessageDigest md_sha=null;
	
	private final int numRecurseDigest=6;
	
	public MyHash() throws NoSuchAlgorithmException
	{
		md_sha = MessageDigest.getInstance("SHA-1");
	}
	
	private byte[] getHash(byte[] bytes)
	{
		md_sha.reset();
		
		return md_sha.digest(bytes);
	}
	
	private byte[] hashify(byte[] initVector, byte[] credentials, int saltID)
	{
      boolean hasIV = (initVector != null);
      int capacity = 0;
      
      if (hasIV)
         capacity = initVector.length;
      byte[] salt = Salts.bytes[saltID];
      capacity += credentials.length + salt.length;
      
      byte[] buff = new byte[capacity];
      
      int insertIndex = 0;
      
      if (hasIV)
      	 for(byte b : initVector)
      	    buff[insertIndex++]=b;
		
      for(byte b : credentials)
         buff[insertIndex++]=b;
		
      for(byte b : salt)
         buff[insertIndex++]=b;
      
		return getHash(buff);
	}
	
	public byte[] getCredKey(byte[] credentials)
	{
		byte[] r=null;

		int iterationCounter=0;
		
		while (iterationCounter<=numRecurseDigest)
		{
			r=hashify(r, credentials, Salts.CREDKEY_ID);
			iterationCounter++;
		}
		return r;
	}
	
	public byte[] getHMACKeyFromCredKey(byte[] credentials, byte[] credKey)
	{
		byte[] r=credKey;
		
		int iterationCounter=0;
		
		while (iterationCounter<=numRecurseDigest)
		{
			r=hashify(r, credentials, Salts.HMAC_ID);
			iterationCounter++;
		}
		
		return r;
	}
	
	public byte[] getHMACKeyFromCred(byte[] credentials)
	{
      if (credentials == null)
         return null;
		return getHMACKeyFromCredKey(credentials, getCredKey(credentials));
	}
	
}
