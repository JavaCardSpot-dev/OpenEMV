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
public class RSAkeygen {
    
    // DH safe prime generated using OPENSSL dhparam
    private byte publicexp[] = { 
        
         (byte) 0x01, (byte) 0x00, (byte) 0x01
    };
    
     private byte privateexp[] = { 
     
    (byte) 0x39 ,(byte) 0x58 ,(byte) 0x56 ,(byte) 0x0f ,(byte) 0x7a ,(byte) 0x44 ,(byte) 0x8d ,(byte) 0x94 ,(byte) 0x5d ,
    (byte) 0x81 ,(byte) 0xa7 ,(byte) 0xff ,(byte) 0x97 ,(byte) 0xf6 ,(byte) 0xcf ,(byte) 0x80 ,(byte) 0x12 ,(byte) 0x32 ,
    (byte) 0x6b ,(byte) 0xe3 ,(byte) 0xaf ,(byte) 0x2d ,(byte) 0x9e ,(byte) 0x46 ,(byte) 0x81 ,(byte) 0x87 ,(byte) 0xba ,
    (byte) 0x13 ,(byte) 0x43 ,(byte) 0xcf ,(byte) 0x0c ,(byte) 0x81 ,(byte) 0x72 ,(byte) 0x54 ,(byte) 0x64 ,(byte) 0xd6 ,
    (byte) 0x10 ,(byte) 0x60 ,(byte) 0x05 ,(byte) 0xcd ,(byte) 0x7e ,(byte) 0x72 ,(byte) 0xf2 ,(byte) 0x13 ,(byte) 0xa6 ,
    (byte) 0x88 ,(byte) 0x08 ,(byte) 0x01 ,(byte) 0x45 ,(byte) 0x71 ,(byte) 0xa4 ,(byte) 0x41 ,(byte) 0x64 ,(byte) 0xd5 ,
    (byte) 0xe8 ,(byte) 0xa9 ,(byte) 0xfb ,(byte) 0xa3 ,(byte) 0xd1 ,(byte) 0x99 ,(byte) 0x5d ,(byte) 0x44 ,(byte) 0xfe ,
    (byte) 0x4b ,(byte) 0x87 ,(byte) 0x7d ,(byte) 0x8e ,(byte) 0x90 ,(byte) 0x2a ,(byte) 0x36 ,(byte) 0xcc ,(byte) 0x3e ,
    (byte) 0x43 ,(byte) 0x14 ,(byte) 0x45 ,(byte) 0xf2 ,(byte) 0x79 ,(byte) 0xc5 ,(byte) 0x45 ,(byte) 0x54 ,(byte) 0x7b ,
    (byte) 0x71 ,(byte) 0x9b ,(byte) 0x36 ,(byte) 0x39 ,(byte) 0xa1 ,(byte) 0x59 ,(byte) 0x99 ,(byte) 0xa9 ,(byte) 0x91 ,
    (byte) 0x63 ,(byte) 0xc7 ,(byte) 0xe1 ,(byte) 0xb7 ,(byte) 0x2a ,(byte) 0x8b ,(byte) 0x4c ,(byte) 0x5e ,(byte) 0xb9 ,
    (byte) 0xde ,(byte) 0x11 ,(byte) 0x59 ,(byte) 0x7f ,(byte) 0x87 ,(byte) 0x73 ,(byte) 0x8e ,(byte) 0xf0 ,(byte) 0x3d ,
    (byte) 0x25 ,(byte) 0xc0 ,(byte) 0x8d ,(byte) 0xbf ,(byte) 0xd1 ,(byte) 0x2b ,(byte) 0x50 ,(byte) 0xb2 ,(byte) 0xdf ,
    (byte) 0xbd ,(byte) 0x7e ,(byte) 0x62 ,(byte) 0x0c ,(byte) 0xfb ,(byte) 0xa1 ,(byte) 0x05 ,(byte) 0x78 ,(byte) 0x32 ,
    (byte) 0x2a ,(byte) 0x01

     };
     
    private byte modulus[] = { 
         
    (byte) 0xf9 ,(byte) 0x16 ,(byte) 0x40 ,(byte) 0x33 ,(byte) 0x50 ,(byte) 0x6c ,(byte) 0xb9 ,(byte) 0x06 ,(byte) 0x6e ,
    (byte) 0x97 ,(byte) 0x93 ,(byte) 0x6e ,(byte) 0x7d ,(byte) 0x42 ,(byte) 0x18 ,(byte) 0x47 ,(byte) 0x27 ,(byte) 0xad ,
    (byte) 0x70 ,(byte) 0x7e ,(byte) 0x6c ,(byte) 0x57 ,(byte) 0x19 ,(byte) 0x96 ,(byte) 0xaa ,(byte) 0x2f ,(byte) 0x29 ,
    (byte) 0x73 ,(byte) 0x57 ,(byte) 0x2e ,(byte) 0xb2 ,(byte) 0xe8 ,(byte) 0xe7 ,(byte) 0xaa ,(byte) 0x9b ,(byte) 0x75 ,
    (byte) 0xe8 ,(byte) 0x7c ,(byte) 0x2b ,(byte) 0x1f ,(byte) 0x4a ,(byte) 0xa9 ,(byte) 0xae ,(byte) 0x20 ,(byte) 0x73 ,
    (byte) 0x93 ,(byte) 0x1d ,(byte) 0x34 ,(byte) 0x9f ,(byte) 0x67 ,(byte) 0x98 ,(byte) 0x9e ,(byte) 0xb1 ,(byte) 0xf0 ,
    (byte) 0x7b ,(byte) 0xca ,(byte) 0x52 ,(byte) 0x38 ,(byte) 0x25 ,(byte) 0xf5 ,(byte) 0x64 ,(byte) 0xb0 ,(byte) 0x62 ,
    (byte) 0x04 ,(byte) 0xc9 ,(byte) 0x28 ,(byte) 0x14 ,(byte) 0x8f ,(byte) 0xb5 ,(byte) 0x89 ,(byte) 0xf6 ,(byte) 0xc5 ,
    (byte) 0xd5 ,(byte) 0x77 ,(byte) 0xc9 ,(byte) 0xe2 ,(byte) 0x7b ,(byte) 0xb3 ,(byte) 0xdc ,(byte) 0xfc ,(byte) 0x47 ,
    (byte) 0x91 ,(byte) 0xe9 ,(byte) 0xed ,(byte) 0xae ,(byte) 0x44 ,(byte) 0xed ,(byte) 0xf6 ,(byte) 0x8e ,(byte) 0xda ,
    (byte) 0xd2 ,(byte) 0xf2 ,(byte) 0x68 ,(byte) 0x8b ,(byte) 0x6a ,(byte) 0x7a ,(byte) 0xfb ,(byte) 0xe6 ,(byte) 0xf2 ,
    (byte) 0x48 ,(byte) 0xff ,(byte) 0x7e ,(byte) 0x90 ,(byte) 0x54 ,(byte) 0xc1 ,(byte) 0x81 ,(byte) 0xc1 ,(byte) 0x9d ,
    (byte) 0x3d ,(byte) 0xa7 ,(byte) 0xa0 ,(byte) 0xf3 ,(byte) 0xbe ,(byte) 0x5d ,(byte) 0x7a ,(byte) 0x19 ,(byte) 0xd3 ,
    (byte) 0x61 ,(byte) 0x10 ,(byte) 0x44 ,(byte) 0x85 ,(byte) 0x9c ,(byte) 0x86 ,(byte) 0xc8 ,(byte) 0xd6 ,(byte) 0x32 ,
    (byte) 0x80 ,(byte) 0xe7

    };
    
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
    
    public RSAkeygen()
    {       
         // CREATE RSA KEYS AND PAIR 
         
            encryptCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            decryptCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            m_keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            m_keyPair.genKeyPair(); // Generate fresh key pair on-card
            A = (RSAPublicKey)m_keyPair.getPublic();
            B = (RSAPrivateKey)m_keyPair.getPrivate();
            
           
           
            
    }
    
    public void encrypt()
    { 
            System.out.println("Inside encrypt");
            A.setModulus(modulus, (short) 0, keyLength);
            System.out.println("Setting exponent");
            A.setExponent(publicexp,(short) 0 , (short) 3);
            System.out.println("Initialize cipher");
            encryptCipher.init(A, Cipher.MODE_ENCRYPT);
            System.out.println("do final with data value"+ data);
            encryptCipher.doFinal(data, (short) 0, (short) 128, ciphertext, (short) 0);
            System.out.println(" data = "+ Arrays.toString(data));
            System.out.println(" ciphertext = "+ Arrays.toString(ciphertext));
            
    }
    
     public void decrypt()
    { 
            B.setModulus(modulus, (short) 0, keyLength);
            B.setExponent(privateexp,(short) 0 , (short) 128);
            decryptCipher.init(B, Cipher.MODE_DECRYPT);
            decryptCipher.doFinal(ciphertext, (short) 0, (short) 128, plaintext, (short) 0);
            System.out.println(" plaintext = "+ Arrays.toString(plaintext));
    }
    
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

    
       
}
