/* 
 * Copyright (C) 2011  Digital Security group, Radboud University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package applet;

import org.junit.Assert;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacardx.crypto.*;
import javacard.security.*;
import javax.crypto.*;



 

/* A very basic EMV applet supporting only SDA and plaintext offline PIN.
 * This applet does not offer personalisation support - everything is hard-coded.
 * 
 * The code is optimised for readability, and not for performance or memory use.
 * 
 * This class does the central processing of APDUs. Handling of all crypto-related
 * stuff is outsourced to EMVCrypro, handling of the static card data to EMVStaticData,
 * and handling of the EMV protocol and session state to EMVProtocolState.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * 
 */
public class SimpleEMVApplet extends Applet implements EMVConstants {

	final OwnerPIN pin;
	final RandomData randomData;
	final EMVCrypto theCrypto;
	final EMVProtocolState protocolState;
	final EMVStaticData staticData;
	
	/* Transient byte array for constructing APDU responses. 
	 * We could have used the APDU buffer for this, but then we have to be careful not to 
	 * overwrite any info in the instruction APDU that we still need.
	 */
	private final byte[] response;
	private short memtyperesponse;
        private KeyPair m_keyPair = null;
        private Key m_privateKey = null;
        private Key m_publicKey = null;
        private javacardx.crypto.Cipher encryptCipher = null;
        private javacardx.crypto.Cipher decryptCipher = null;
        private RSAPublicKey  CardPubkey = null;
        private RSAPrivateKey  CardPrivkey = null;
        private byte CardSignature []= null;
        private byte CardModulus []= null;
        byte [] datatemp = null;
        short []atcpersistent = new short[1];
        //private RSAApplet rsaapp = null;
	private SimpleEMVApplet() {
               
                datatemp = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
		response = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);

		pin = new OwnerPIN((byte) 3, (byte) 2);
		pin.update(new byte[] { (byte) 0x12, (byte) 0x34 }, (short) 0, (byte) 2);
		randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		
		protocolState = new EMVProtocolState(this);
		staticData = new EMVStaticData();
		theCrypto = new EMVCrypto(this);
                memtyperesponse = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
                
                // RSA ......
                encryptCipher = javacardx.crypto.Cipher.getInstance(javacardx.crypto.Cipher.ALG_RSA_NOPAD, false);
                decryptCipher = javacardx.crypto.Cipher.getInstance(javacardx.crypto.Cipher.ALG_RSA_NOPAD, false);
               
	} 

	/**
	 * Installs an instance of the applet.
	 * 
	 * @see javacard.framework.Applet#install(byte[], byte, byte)
	 */
	public static void install(byte[] buffer, short offset, byte length) {
		(new SimpleEMVApplet()).register();
	}

	/**
	 * Processes incoming APDUs.
	 * 
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte cla = apduBuffer[OFFSET_CLA];
		byte ins = apduBuffer[OFFSET_INS];

		if (selectingApplet()) {
			// Reset all the flags recording the protocol state.
			// This should already have happened by the clearing of the
			// transient array used for them.
			protocolState.startNewSession(atcpersistent[1]);
			
			apdu.setOutgoing();
			apdu.setOutgoingLength(staticData.getFCILength());
			apdu.sendBytesLong(staticData.getFCI(), (short)0, staticData.getFCILength());
			return;
		}
                
		switch (ins) {

		case INS_EXTERNAL_AUTHENTICATE: // 0x82
			break;

		case INS_GET_CHALLENGE: // 0x84
			getChallenge(apdu, apduBuffer);
			break;

		case INS_INTERNAL_AUTHENTICATE:
			break;

		case INS_READ_RECORD: // 0xB2
			readRecord(apdu, apduBuffer);
			break;

		case INS_GET_PROCESSING_OPTIONS: // 0xA8
			getProcessingOptions(apdu, apduBuffer);
			break;

		case INS_GET_DATA: // 0xCA
			getData(apdu, apduBuffer);
			break;

		case INS_VERIFY: // 0x20
			verifyPIN(apdu, apduBuffer);
			break;
                case INS_MEMORY: // 0xAA
			getMemory(apdu, apduBuffer);
			break;
                case INS_ISSUER_SENDPUB:
                        sendPub(apdu, apduBuffer);
                    break;
                case INS_CARD_SIGNATURE:
                        storesignature(apdu, apduBuffer);
                        break;
                case INS_GET_SIGNATURE:
                         getsignature(apdu, apduBuffer);
                    break;
                        
                    
		case INS_GENERATE_AC: // 0xAE
			// get remaining data
			short len = (short) (apduBuffer[OFFSET_LC] & 0xFF);
			if (len != apdu.setIncomingAndReceive()) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			// check for request of CDA signature
			if ((apduBuffer[OFFSET_P1] & 0x10) == 0x10) {
				// CDA signature requested, which we don't support (yet)
				ISOException.throwIt(SW_WRONG_P1P2);
			}
			if (protocolState.getFirstACGenerated() == NONE) {
				generateFirstAC(apdu, apduBuffer);
			} else if (protocolState.getSecondACGenerated() == NONE) {
				generateSecondAC(apdu, apduBuffer);
			} else
				// trying to generate a third AC
				ISOException.throwIt(SW_INS_NOT_SUPPORTED);
			break;

		// below the (unsupported) post-issuance commands
		case INS_APPLICATION_BLOCK:
		case INS_APPLICATION_UNBLOCK:
		case INS_CARD_BLOCK:
		case INS_PIN_CHANGE_UNBLOCK:
		default:
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
			break;
		}
	}
 
	/*
	 * The VERIFY command checks the pin. This implementation only supports
	 * transaction_data PIN.
	 */	
	private void verifyPIN(APDU apdu, byte[] apduBuffer) {
		if (apduBuffer[OFFSET_P2] != ((byte) (0x88) | (byte) (0x80))) {
			ISOException.throwIt(SW_WRONG_P1P2); // we only support transaction_data PIN
		}
		if (pin.getTriesRemaining() == 0) 
		{
			ISOException.throwIt((short) 0x6983); // PIN blocked
			return;
		}
                if(apduBuffer[OFFSET_P2] == (byte) 0x88)
                {
                 byte []temp = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);   
                 Util.arrayCopyNonAtomic(apduBuffer , (short) 5,temp , (short)0, (short)128);   
                 encryptCipher.init(CardPrivkey, javacardx.crypto.Cipher.MODE_ENCRYPT);
                 encryptCipher.doFinal(temp, (short) 0, (short) 128, temp, (short) 0);
                  Util.arrayCopyNonAtomic(temp , (short) 0,apduBuffer , (short)0, (short)128);   
                 apdu.setOutgoingAndSend((short) 0, (short) 128);
                }

		/* EP: For the code below to be correct, digits in the PIN object need
		 * to be coded in the same way as in the APDU, ie. using 4 bit words.
		 */
                else{
		if (pin.check(apduBuffer, (short) (OFFSET_CDATA + 1), (byte) 2)) 
		{
			protocolState.setCVMPerformed(PLAINTEXT_PIN);
			apdu.setOutgoingAndSend((short) 0, (short) 0); // return 9000
		} 
		else 
		{
			ISOException.throwIt((short) ((short) (0x63C0) + (short) pin.getTriesRemaining()));
		}
                }
	}

	/*
	 * The GET CHALLENGE command generates an 8 byte unpredictable number.
	 */
	private void getChallenge(APDU apdu, byte[] apduBuffer) {
		randomData.generateData(apduBuffer, (short) 0, (short) 8);
		apdu.setOutgoingAndSend((short) 0, (short) 8);
	}

	/*
	 * The GET DATA command is used to retrieve a primitive data object not
	 * encapsulated in a record within the current application.
	 * 
	 * The usage of GET DATA in this implementation is limited to the ATC,
	 * the PIN Try Counter, and the last online ATC.
	 */
	 //���ڼ�����ǰ��Ӧ�ó�����û�б���װ����¼�е�ԭʼ���ݶ��󡡡�
	 //GET DATA ��ʵ��ȡ����ATC�� PIN���Դ�������������ߵ�ATC��
	private void getData(APDU apdu, byte[] apduBuffer) {
		/*
		 * buffer[OFFSET_P1..OFFSET_P2] should contains of the following tags
		 *  9F36 - ATC 
		 *  9F17 - PIN Try Counter 
		 *  9F13 - Last online ATC 
		 *  9F4F - Log Format
		 */
		if (apduBuffer[OFFSET_P1] == (byte) 0x9F) {
			apduBuffer[0] = (byte) 0x9F;
			apduBuffer[1] = apduBuffer[OFFSET_P2];
			switch (apduBuffer[OFFSET_P2]) {
			// The apduBuffer[OFFSET_P1,OFFSET_P2] already contains the right Tag,
			// so we can write the Length and Value to the next bytes in the apduBuffer
			// and then send this.
			case 0x36: // ATC
				apduBuffer[OFFSET_P2 + 1] = (byte) 0x02; // length 2 bytes
				Util.setShort(apduBuffer, (short) (OFFSET_P2 + 2), protocolState.getATC()); // value
				// send the 5 byte long TLV for ATC
				apdu.setOutgoingAndSend(OFFSET_P1, (short) 5); 
				break;

			case 0x17: // PIN Try Counter
				apduBuffer[OFFSET_P2 + 1] = (byte) 0x01; // length 1 byte
				apduBuffer[OFFSET_P2 + 2] = pin.getTriesRemaining(); // value
				// send the 4 byte TLV for PIN Try counter
				apdu.setOutgoingAndSend(OFFSET_P1, (short) 4); 
				break;

			case 0x13: // Last online ATC
				apduBuffer[OFFSET_P2 + 1] = (byte) 0x02; // length 2 bytes
				Util.setShort(apduBuffer, (short) (OFFSET_P2 + 2), protocolState.getLastOnlineATC()); // value
				// send the 5 byte long TLV for last online ATC
				apdu.setOutgoingAndSend(OFFSET_P1, (short) 5);  
				break;
			case 0x4F: // Log Format - not supported yet
			default:
				ISOException.throwIt(SW_WRONG_P1P2);
				break;
			}
		}
	}

	private void readRecord(APDU apdu, byte[] apduBuffer) {
		staticData.readRecord(apduBuffer, response);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(response[1]+2));
		apdu.sendBytesLong(response, (short)0, (short)(response[1]+2));
	}
        
        
        
        private void getMemory(APDU apdu, byte[] apduBuffer) {
            byte[] ret = new byte[2];
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)8);
                ret[0] = (byte)(memtyperesponse & 0xff);
                ret[1] = (byte)((memtyperesponse >> 8) & 0xff);
		apdu.sendBytesLong(ret, (short)0, (short)2);	
	}

	private void getProcessingOptions(APDU apdu, byte[] apduBuffer) {
		// TODO Check APDU? PDOL is not checked at the moment
		
		// Return data using Format 1 
		response[0] = (byte) 0x80; // Tag
		response[1] = (byte) 0x06; // Length
		
		// 2 byte Application Interchange Profile 
		Util.setShort(response, (short)2, staticData.getAIP()); 
		
		// 4 byte Application File Locator
		Util.arrayCopyNonAtomic(staticData.getAFL(), (short)0, response, (short)4, (short)4);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)8);
		apdu.sendBytesLong(response, (short)0, (short)8);		
	}

	public void generateFirstAC(APDU apdu, byte[] apduBuffer) {
		// First 2 bits of P1 specify the type
		// These bits also have to be returned, as the Cryptogram Information Data (CID);
		// See Book 3, Annex C6.5.5.4 
		byte cid = (byte) (apduBuffer[OFFSET_P1] & 0xC0);
		if (cid == RFU_CODE || cid == AAC_CODE) {
			// not a request for TC or ARQC
			ISOException.throwIt(SW_WRONG_P1P2);
		}
		
		theCrypto.generateFirstACReponse(cid, apduBuffer, staticData.getCDOL1DataLength(), null, (short)0, response, (short)0);
		protocolState.setFirstACGenerated(cid);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(response[1]+2));
		apdu.sendBytesLong(response, (short)0, (short)(response[1]+2));		
	}
 
	public void generateSecondAC(APDU apdu, byte[] apduBuffer) {
		// First 2 bits of P1 specify the type
		// These bits also have to be returned, as the Cryptogram Information Data (CID);
		// See Book 3, Sect 6.5.5.4 of the Common Core Definitions.
		byte cid = (byte) (apduBuffer[OFFSET_P1] & 0xC0);
		if (cid == RFU_CODE || cid == ARQC_CODE) {
			// not a request for TC or AAC
			ISOException.throwIt(SW_WRONG_P1P2);
		}	

		theCrypto.generateSecondACReponse(cid, apduBuffer, staticData.getCDOL2DataLength(), null, (short)0, response, (short)0);
		protocolState.setSecondACGenerated(cid);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(response[1]+2));
		apdu.sendBytesLong(response, (short)0, (short)(response[1]+2));		
	}
        
        private void sendPub(APDU apdu, byte[] apduBuffer) {
            
            CardModulus = new byte[128];
            m_keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            m_keyPair.genKeyPair(); // Generate fresh key pair on-card
            byte cid = (byte) (apduBuffer[OFFSET_P1] & 0x11);
		if (cid == SIMULATED_MODE) {
                    CardPubkey = (RSAPublicKey)m_keyPair.getPublic();
                    CardPrivkey = (RSAPrivateKey)m_keyPair.getPrivate();
                    CardPubkey.setModulus(staticData.sim_mod, (short) 0, (short)128);
                    CardPubkey.setExponent(staticData.sim_publicexp,(short) 0 , (short) 3);
                    CardPrivkey.setModulus(staticData.sim_mod, (short) 0, (short)128);
                    CardPrivkey.setExponent(staticData.sim_privexp,(short) 0 , (short) 128);
                    CardPubkey.getModulus(CardModulus, (short) 0);
		}
		// CREATE RSA KEYS AND PAIR 
                else{   
                       
            m_publicKey = m_keyPair.getPublic();
            m_privateKey = m_keyPair.getPrivate();
            CardPubkey = (RSAPublicKey)m_keyPair.getPublic();
            CardPrivkey = (RSAPrivateKey)m_keyPair.getPrivate();
            
            //CardPubkey.getExponent(datatemp, (short) 0);
            CardPubkey.getModulus(CardModulus, (short) 0);
            
                }
           // System.out.println(" carpubkey = "+ Arrays.toString(datatemp));
            Util.arrayCopyNonAtomic(CardModulus, (short) 0, apduBuffer, (short) 0, (short)128);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short) 0, (short)128);

	}
    
        private void storesignature(APDU apdu, byte[] apduBuffer) {
            
            
            CardSignature = new byte[128];
            
            Util.arrayCopyNonAtomic(apduBuffer, (short) 5,CardSignature , (short)0, (short)128);
            //System.out.println("card signature at applet" + CardSignature);
            
            Util.arrayCopyNonAtomic(CardSignature, (short) 0, apduBuffer, (short) 0, (short)128);
            apdu.setOutgoingAndSend((short) 0, (short)128);

            
        }
	
        private void getsignature(APDU apdu, byte[] apduBuffer) {
            
    
           
            
           
            byte cid = (byte) (apduBuffer[OFFSET_P1] & 0x11);
		if (cid == SIMULATED_MODE) {
                    CardModulus = new byte[128];
                    m_keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
                    m_keyPair.genKeyPair(); // Generate fresh key pair on-card
                    CardPubkey = (RSAPublicKey)m_keyPair.getPublic();
                    CardPrivkey = (RSAPrivateKey)m_keyPair.getPrivate();
                    CardPubkey.setModulus(staticData.sim_mod, (short) 0, (short)128);
                    CardPubkey.setExponent(staticData.sim_publicexp,(short) 0 , (short) 3);
                    CardPrivkey.setModulus(staticData.sim_mod, (short) 0, (short)128);
                    CardPrivkey.setExponent(staticData.sim_privexp,(short) 0 , (short) 128);
                    CardPubkey.getModulus(CardModulus, (short) 0);
                    Util.arrayCopyNonAtomic(CardModulus , (short) 0,apduBuffer , (short)0, (short)128);
                    Util.arrayCopyNonAtomic(staticData.sim_cardsignature , (short) 0,apduBuffer , (short)128, (short)128);
		}
                else{
                    Util.arrayCopyNonAtomic(CardModulus , (short) 0,apduBuffer , (short)0, (short)128);
             Util.arrayCopyNonAtomic(CardSignature , (short) 0,apduBuffer , (short)128, (short)128);
                }
            
            
            
           //System.out.println("card signature at applet" + CardSignature);
            
             
             apdu.setOutgoingAndSend((short) 0, (short)256);

            
        }
}
