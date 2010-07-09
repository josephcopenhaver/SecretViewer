/**
 * @(#)SecretViewer.java
 *
 * SecretViewer application
 *
 * @author 
 * @version 1.00 2010/3/30
 */
 
import java.awt.TextArea;
import java.awt.Menu;
import java.awt.MenuItem;
import java.awt.MenuShortcut;
import java.awt.MenuBar;
import java.awt.Frame;

import java.awt.event.WindowAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.WindowEvent;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;

import java.io.File;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.util.Arrays;
 
public class SecretViewer extends Frame
{
   
   private static final int HMAC_SIZE = 20;
   
   private static final long serialVersionUID = 1;
   
   private File openFile = null;
   
   TextArea textArea = new TextArea();
   
   private MenuItem fr,fo,fs,fsa,fn,fc;
   
   private String currentDirectory = null;
   
   private static final String frameTitle = "SecretViewer";
   private JFileChooser jfc = null;
   private byte[] HMACKey = null;
   private MyCipher myCipher = null;
   private MyHash myHash = null;
   private JPasswordField passField = null;
   
   private SecretViewer(String currentDirectory) throws NoSuchAlgorithmException
   {
      super(frameTitle);
      this.currentDirectory = currentDirectory;
      myCipher = new MyCipher();
      myHash = myCipher.getMyHash();
      jfc = new JFileChooser(currentDirectory);
      
      passField = new JPasswordField(20);
      
      // Set master window close function
      addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent e){
         dispose();
      }});
      
      
      Menu m = new Menu("File",true);
      
      fr = new MenuItem("Reset",new MenuShortcut(KeyEvent.VK_R));
      fr.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
         reset();
      }});
      m.add(fr);
      
      fo = new MenuItem("Open",new MenuShortcut(KeyEvent.VK_O));
      fo.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
         open();
      }});
      m.add(fo);
      
      fs = new MenuItem("Save",new MenuShortcut(KeyEvent.VK_S));
      fs.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
         save();
      }});
      m.add(fs);
      
      fsa = new MenuItem("Save As",new MenuShortcut(KeyEvent.VK_S,true));
      fsa.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
         saveAs();
      }});
      m.add(fsa);
      
      fn = new MenuItem("New Window",new MenuShortcut(KeyEvent.VK_N));
      fn.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
         createNew();
      }});
      m.add(fn);
      
      fc = new MenuItem("Close Window",new MenuShortcut(KeyEvent.VK_X,true));
      fc.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
         dispose();
      }});
      m.add(fc);
      
      MenuBar mb = new MenuBar();
      mb.add(m);
      setMenuBar(mb);
      add(textArea);
      setSize(500,500);

      pack();
      setVisible(true);
   }
   
   private boolean doubleCheck(String msg)
   {
       return (JOptionPane.showConfirmDialog(this,msg + "\nAre you sure you wish to continue?","Really?",0) == JOptionPane.OK_OPTION);
   }
   
   private void warn(String msg)
   {
       JOptionPane.showMessageDialog(this, msg, "Warning", JOptionPane.ERROR_MESSAGE);
   }
   
   private boolean hasContent()
   {
       String content = textArea.getText();
       return !(content == null || content.equals(""));
   }
   
   private File selectFile()
   {
       if (jfc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
       {
          currentDirectory = jfc.getCurrentDirectory().toString();
          return jfc.getSelectedFile();
       }
       
       return null;
   }
   
   private String promptSecretString(String msg)
   {
      JOptionPane.showMessageDialog(this, new Object[] { msg, passField }, msg, JOptionPane.QUESTION_MESSAGE);
      String input = new String(passField.getPassword());
       passField.setText("");
       if (input != null)
      {
         input=input.trim();
        if (input.length() == 0)
            input=null;
      }
     
       return input;
   }
   
   private boolean reset()
   {
     return reset(false, true);
   }
   
   private boolean reset(boolean force)
   {
     return reset(force, true);
   }
   
   private boolean reset(boolean force, boolean commit)
   {
     boolean doReset = force;
     boolean rval = false;
     
     
      if (!doReset)
         if (openFile != null)
            doReset = (doubleCheck("The file: \"" + openFile.getAbsolutePath() + "\" is currently open!\nAny unsaved changes will be lost!"));
        else if (hasContent())
           doReset = (doubleCheck("Any unsaved changes will be lost!"));
        else
           rval=true;   // This means we are already reset!
    
    
     if (doReset)
     {
        rval = true;
         if (commit)
         {
            openFile = null;
            HMACKey=null;
            textArea.setText("");
            setTitle(frameTitle);
         }
     }
      
      return rval;
   }
   
   private boolean open()
   {
      textArea.setEnabled(false);
      boolean rval = false;
      if (reset())
      {
         openFile = selectFile();
         if (openFile != null)
         {
            if (!openFile.exists())
                warn("The file: " + openFile.getAbsolutePath() + " does not exist!");
            else
            {
               String pass = promptSecretString("Enter the password");
            
               if (pass == null)
                  warn("Password was empty!");
               else
               {
                  try
                  {
                     BufferedInputStream in = new BufferedInputStream(new FileInputStream(openFile));
                     byte[] fileHMAC = new byte[HMAC_SIZE];
                     in.read(fileHMAC);
                     byte[] cryptoBytes = new byte[in.available()];
                     in.read(cryptoBytes);
                     myCipher.setCipherMode(MyCipher.DECRYPT_MODE);
                     myCipher.init(pass.getBytes());
                     HMACKey = myCipher.getHMACKey();
                     boolean hmacIsValid = Arrays.equals(fileHMAC, myCipher.getHMAC(HMACKey, cryptoBytes));
                     Exception decryptionException = null;
                     try
                     {
                        textArea.setText(new String(myCipher.doFinal(cryptoBytes)));
                     }
                     catch(Exception e)
                     {
                        decryptionException = e;
                     }
                     
                     if (hmacIsValid)
                     {
                        if (decryptionException == null)
                        {
                           setTitle(frameTitle + " - " + openFile.getAbsolutePath());
                           rval = true;
                        }
                        else
                        {
                           warn("The file " + "passed" + " HMAC verification" + ", but " + "failed" + " decryption: " + decryptionException.getMessage() + "!\nIncorrect password or file has been modified!");
                        }
                     }
                     else
                     {
                        if (decryptionException == null)
                        {
                           setTitle(frameTitle + " (Corrupted) - " + openFile.getAbsolutePath());
                           rval = true;
                           warn("The file " + "failed" + " HMAC verification" + ", but " + "passed" + " decryption" + "!\nIncorrect password or file has been modified!");
                        }
                        else
                        {
                           warn("The file " + "failed" + " HMAC verification" + " and " + "failed" + " decryption: " + decryptionException.getMessage() + "!\nIncorrect password or file has been modified!");
                        }
                     }
                  }
                  catch (NoSuchPaddingException e)
                  {
                     warn("ERR: A crypto no such padding Exception occured: " + e.getMessage() + "!");
                  }
                  catch (FileNotFoundException e)
                  {
                     warn("ERR: Could not locate the file \"" + openFile.getAbsolutePath() + "\" : " + e.getMessage() + "!");
                  }
                  catch (IOException e)
                  {
                     warn("ERR: An IO Exception occured while accessing \"" + openFile.getAbsolutePath() + "\" : " + e.getMessage() + "!\nAre you sure this is an encrypted file?");
                  }
                  catch (NoSuchAlgorithmException e)
                  {
                     warn("ERR: A java algorithm is missing: " + e.getMessage() + "!");
                  }
                  catch (InvalidKeyException e)
                  {
                     warn("ERR: A crypto invalid key Exception occured: " + e.getMessage() + "!\nAre you sure this is an encrypted file?");
                  }
               }
               
               pass=null;

            }
         
         }
         if (!rval)
            reset(true);
      }
      
      
      textArea.setEnabled(true);
      
      return rval;
   }
   
   private boolean save()
   {
      if (openFile == null)
         return saveAs();
      textArea.setEnabled(false);
      boolean rval=false;
      if (hasContent() || doubleCheck("There is nothing to save!"))
      {
         String pass = promptSecretString("Enter the password");
         byte[] _pass;
         if (pass == null)
            warn("Password was empty!");
         else
         {
            _pass = pass.getBytes();
            pass = null;
            if (!Arrays.equals(myHash.getHMACKeyFromCred(_pass), HMACKey))
               warn("Incorrect password!\nTry saving as a new file to set a new password.");
            else
            {
               myCipher.setCipherMode(MyCipher.ENCRYPT_MODE);
               try
               {
                  myCipher.init(_pass);
                  BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(openFile));
                  byte[] hmackey = myCipher.getHMACKey();
                  byte[] cryptoMessage = myCipher.doFinal(textArea.getText().getBytes());
                  out.write(myCipher.getHMAC(hmackey, cryptoMessage));
                  out.write(cryptoMessage);
                  out.flush();
                  out.close();
                  reset(true);
                  rval=true;
               }
               catch (BadPaddingException e)
               {
                  warn("ERR: A crypto bad padding Exception occured: " + e.getMessage() + "!");
               }
               catch (NoSuchPaddingException e)
               {
                  warn("ERR: A crypto no such padding Exception occured: " + e.getMessage() + "!");
               }
               catch (IllegalBlockSizeException e)
               {
                  warn("ERR: A crypto block size Exception occured: " + e.getMessage() + "!");
               }
               catch (InvalidKeyException e)
               {
                  warn("ERR: A crypto invalid key Exception occured: " + e.getMessage() + "!");
               }
               catch (NoSuchAlgorithmException e)
               {
                  warn("ERR: A java algorithm is missing: " + e.getMessage() + "!");
               }
               catch(IOException e)
               {
                  warn("ERR: IOException occured while accessing \"" + openFile.getAbsolutePath() + "\" : " + e.getMessage() + "!");
               }
            }
               
         }
         pass=null;
         _pass=null;
         if (!rval)
            warn("Data was NOT saved!");
      }
      
      textArea.setEnabled(true);
      
     return rval;
   }
   
   private boolean saveAs()
   {
      textArea.setEnabled(false);
      boolean rval=false;
      if (hasContent() || doubleCheck("There is nothing to save!"))
      {
         File file = selectFile();
         if (file == null)
            warn("No file was selected!");
         else if (!file.exists() || doubleCheck("This will overwrite the existing file."))
         {
            String pass = promptSecretString("Enter a new password");
            if (pass == null)
               warn("Password was empty!");
            else
            {
               String pass2 = promptSecretString("Re-enter the password");
               if (pass2 == null || !pass.equals(pass2))
                  warn("Passwords do not match!");
               else
               {
                  myCipher.setCipherMode(MyCipher.ENCRYPT_MODE);
                  try
                  {
                     myCipher.init(pass2.getBytes());
                     BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(file));
                     byte[] hmackey = myCipher.getHMACKey();
                     byte[] cryptoMessage = myCipher.doFinal(textArea.getText().getBytes());
                     out.write(myCipher.getHMAC(hmackey, cryptoMessage));
                     out.write(cryptoMessage);
                     out.flush();
                     out.close();
                     file = null;
                     reset(true);
                     rval=true;
                  }
                  catch (BadPaddingException e)
                  {
                     warn("ERR: A crypto bad padding Exception occured: " + e.getMessage() + "!");
                  }
                  catch (NoSuchPaddingException e)
                  {
                     warn("ERR: A crypto no such padding Exception occured: " + e.getMessage() + "!");
                  }
                  catch (IllegalBlockSizeException e)
                  {
                     warn("ERR: A crypto block size Exception occured: " + e.getMessage() + "!");
                  }
                  catch (InvalidKeyException e)
                  {
                     warn("ERR: A crypto invalid key Exception occured: " + e.getMessage() + "!");
                  }
                  catch (NoSuchAlgorithmException e)
                  {
                     warn("ERR: A java algorithm is missing: " + e.getMessage() + "!");
                  }
                  catch(IOException e)
                  {
                     warn("ERR: IOException occured while accessing \"" + openFile.getAbsolutePath() + "\" : " + e.getMessage() + "!");
                  }
               }
               pass=null;
               pass2=null;
            }
         }
         if (!rval)
            warn("Data was NOT saved!");
        }
      
      textArea.setEnabled(true);
     
      return rval;
   }
   
   private boolean createNew()
   {
      try
      {
            new SecretViewer(currentDirectory);
      }
      catch(Exception e)
      {
         warn("ERR: " + e.getMessage());
         return false;
      }
      return true;
   }
   
   public void dispose()
   {
      if (reset(false, false))
        super.dispose();
   }
   
   public static void main(String[] args) throws Exception
   {
      new SecretViewer(null);
   }
   
}
