/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package applet;

import java.util.Arrays;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.CryptoException;

/**
 *
 * @author chintan
 */
public class RSACard {
    
    // DH safe prime generated using OPENSSL dhparam
    private byte publicexp[] = { 
        
         (byte) 0x01, (byte) 0x00, (byte) 0x01
    };
    
     
     
    private byte modulus[] = new byte[128];
    
    public static final short keyLength = 128;
    private byte ciphertext[] =  new byte[128];//JCSystem.makeTransientByteArray(keyLength, JCSystem.CLEAR_ON_RESET); //b = g^A mod modulus
    private byte plaintext[] =  JCSystem.makeTransientByteArray(keyLength, JCSystem.CLEAR_ON_DESELECT); //b = g^A mod modulus
    private KeyPair m_keyPair = null;
    private RSAPublicKey  A = null;
    private RSAPrivateKey  B = null;// m_privateKey <- A
    private Key m_publicKey = null;
    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    private byte data[]= JCSystem.makeTransientByteArray(keyLength, JCSystem.CLEAR_ON_DESELECT);
    private short datalen ;
    
    public RSACard()
    {       
         // CREATE RSA KEYS AND PAIR 
         
            encryptCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            decryptCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            m_keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            m_keyPair.genKeyPair(); // Generate fresh key pair on-card
            A = (RSAPublicKey)m_keyPair.getPublic();
           // B = (RSAPrivateKey)m_keyPair.getPrivate();
            
           
           
            
    }
    
    public void encrypt()
    { 
            A.setModulus(modulus, (short) 0, keyLength);
            A.setExponent(publicexp,(short) 0 , (short) 3);
            encryptCipher.init(A, Cipher.MODE_ENCRYPT);
            encryptCipher.doFinal(data, (short) 0, (short) 128, ciphertext, (short) 0);
            System.out.println(" data = "+ Arrays.toString(data));
            System.out.println(" ciphertext = "+ Arrays.toString(ciphertext));
            
    }
    
    /* public void decrypt()
    { 
            B.setModulus(modulus, (short) 0, keyLength);
            B.setExponent(privateexp,(short) 0 , (short) 128);
            decryptCipher.init(B, Cipher.MODE_DECRYPT);
            decryptCipher.doFinal(ciphertext, (short) 0, (short) 128, plaintext, (short) 0);
            System.out.println(" plaintext = "+ Arrays.toString(plaintext));
    }*/
    
    public void setdata(byte[] src, short offset, short len)
    {
        System.arraycopy(src, offset, data, (short)0, len);
        System.out.println(" Setting G (at apdu) = "+ Arrays.toString(data));
        datalen = len;
    }
    
    public void setciphertext(byte[] src, short offset, short len)
    {
        System.arraycopy(src, offset, ciphertext, (short)0, len);
        System.out.println(" Setting G (at apdu) = "+ Arrays.toString(ciphertext));
        datalen = len;
    }
    

    
    public void getciphertext(byte[] src, short offset, short len)
    {
        System.arraycopy(ciphertext, (short)0, src, offset , len);
    }
    
    public void getplaintext(byte[] src, short offset, short len)
    {
        System.arraycopy(plaintext, (short)0, src, offset , datalen);
    }

    public void setModulus(byte[] src, short offset, short len)
    {
         System.arraycopy(src,offset , modulus, (short)0 , len);
        
    }
   
}
