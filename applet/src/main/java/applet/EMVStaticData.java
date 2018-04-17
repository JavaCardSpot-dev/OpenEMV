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

import javacard.framework.ISOException;
import javacard.framework.Util;

/* Class to record all the static data of an EMV applet, ie. the card details that
 * do not change over time (such as PAN, expiry date, etc.), with the exception
 * of the cryptographic keys.
 * 
 * This static data is organised in the simplest possible way, using some public byte
 * arrays to record exact APDUs that the card has to produce.
 * 
 * This class does not offer personalisation support - everything is hard-coded.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 *
 */

public class EMVStaticData implements EMVConstants {

	private final byte[] theAFL = new byte[]{ (byte)0x08, 0x01, 0x03, 0x01}; // AFL from Dutch bank cards;

	/** Returns the 4 byte AFL (Application File Locator)  */
	public byte[] getAFL(){
	    return theAFL;
	}
        
        public byte sim_cardsignature[]= {
          (byte)0x09,(byte)0xD5,(byte)0x89,(byte)0xEE,(byte)0xE8,(byte)0xEC,(byte)0x9D,(byte)0xBA,
          (byte)0xBD,(byte)0xAC,(byte)0x50,(byte)0x92,(byte)0x4D,(byte)0xA1,(byte)0x78,(byte)0xF9,
          (byte)0x01,(byte)0xEE,(byte)0x99,(byte)0xB3,(byte)0x20,(byte)0x4F,(byte)0x26,(byte)0x5E,
          (byte)0x21,(byte)0x50,(byte)0x19,(byte)0x1E,(byte)0x91,(byte)0xE5,(byte)0x27,(byte)0x31,
          (byte)0x9C,(byte)0xBA,(byte)0xC2,(byte)0x7E,(byte)0xBF,(byte)0x3B,(byte)0x74,(byte)0x83,
          (byte)0x78,(byte)0x61,(byte)0x78,(byte)0x19,(byte)0xA7,(byte)0xBC,(byte)0x01,(byte)0x5E,
          (byte)0x53,(byte)0x64,(byte)0xC1,(byte)0xAF,(byte)0xD9,(byte)0x78,(byte)0xF0,(byte)0x54,
          (byte)0x23,(byte)0x8F,(byte)0xB2,(byte)0x4A,(byte)0xAD,(byte)0xA4,(byte)0x3F,(byte)0x1B,
          (byte)0xEC,(byte)0x99,(byte)0x75,(byte)0x0F,(byte)0x62,(byte)0x7B,(byte)0xB6,(byte)0x4D,
          (byte)0xA0,(byte)0x49,(byte)0xAA,(byte)0xB8,(byte)0x8F,(byte)0x46,(byte)0xF2,(byte)0xFF,
          (byte)0x87,(byte)0x9C,(byte)0x11,(byte)0xB0,(byte)0xD4,(byte)0x66,(byte)0x6B,(byte)0xE2,
          (byte)0x5E,(byte)0x26,(byte)0xCB,(byte)0x98,(byte)0xA4,(byte)0xD4,(byte)0xE7,(byte)0xBA,
          (byte)0x91,(byte)0xA8,(byte)0x5A,(byte)0x0D,(byte)0x22,(byte)0x7A,(byte)0x7D,(byte)0x5D,
          (byte)0xB3,(byte)0x16,(byte)0x2F,(byte)0xCC,(byte)0xE7,(byte)0x03,(byte)0xBA,(byte)0x31,
          (byte)0x4E,(byte)0xF6,(byte)0xBC,(byte)0xB4,(byte)0xA0,(byte)0x26,(byte)0xF2,(byte)0xF6,
          (byte)0x9C,(byte)0x0E,(byte)0xD1,(byte)0xAB,(byte)0x37,(byte)0xC6,(byte)0x75,(byte)0x50  
        };
        public byte sim_publicexp[] = { 
        
         (byte) 0x01, (byte) 0x00, (byte) 0x01
        };
        public final byte[] sim_mod = new byte[]{

        (byte) 0xAF, (byte) 0xFC, (byte) 0xA0, (byte) 0xC2, (byte) 0x00, (byte) 0x2F, (byte) 0xF4, (byte) 0xFF, 
        (byte) 0xBE, (byte) 0xEE, (byte) 0x96, (byte) 0x84, (byte) 0xAA, (byte) 0x31, (byte) 0x0C, (byte) 0x74, (byte) 0xAA, 
        (byte) 0x47, (byte) 0x27, (byte) 0x78, (byte) 0xEA, (byte) 0x5C, (byte) 0x44, (byte) 0xF8, (byte) 0x4B, (byte) 0x85, 
        (byte) 0xF3, (byte) 0xBE, (byte) 0xDA, (byte) 0x5E, (byte) 0xDC, (byte) 0x6A, (byte) 0x95, (byte) 0x88, (byte) 0x5B, 
        (byte) 0x3D, (byte) 0x81, (byte) 0x3C, (byte) 0x41, (byte) 0x1F, (byte) 0xAA, (byte) 0x42, (byte) 0xB8, (byte) 0x78, 
        (byte) 0x93, (byte) 0x7A, (byte) 0x51, (byte) 0x5D, (byte) 0x01, (byte) 0x87, (byte) 0x32, (byte) 0x7B, (byte) 0x12, 
        (byte) 0x45, (byte) 0xDC, (byte) 0xFE, (byte) 0x2A, (byte) 0x7A, (byte) 0x70, (byte) 0x08, (byte) 0xBD, (byte) 0x02, 
        (byte) 0x84, (byte) 0x0A, (byte) 0x74, (byte) 0xE0, (byte) 0x73, (byte) 0x63, (byte) 0x1D, (byte) 0x01, (byte) 0xE1, 
        (byte) 0x9C, (byte) 0x39, (byte) 0x35, (byte) 0x41, (byte) 0xD3, (byte) 0xCB, (byte) 0x28, (byte) 0x87, (byte) 0xA3, 
        (byte) 0x23, (byte) 0x38, (byte) 0x89, (byte) 0xCA, (byte) 0x2B, (byte) 0xB4, (byte) 0x03, (byte) 0x29, (byte) 0xD3, 
        (byte) 0xDF, (byte) 0x1D, (byte) 0x88, (byte) 0x2C, (byte) 0x1E, (byte) 0x2C, (byte) 0x7F, (byte) 0x5E, (byte) 0x86, 
        (byte) 0x2A, (byte) 0x38, (byte) 0x80, (byte) 0x23, (byte) 0x35, (byte) 0x4E, (byte) 0x57, (byte) 0xB4, (byte) 0x8D, 
        (byte) 0xE1, (byte) 0x69, (byte) 0x3E, (byte) 0x67, (byte) 0x9D, (byte) 0xD6, (byte) 0xDF, (byte) 0xCF, (byte) 0x66, 
        (byte) 0x35, (byte) 0x03, (byte) 0x63, (byte) 0x36, (byte) 0x87, (byte) 0x45, (byte) 0xA6, (byte) 0x8B, (byte) 0x17, 
        (byte) 0xE0, (byte) 0x29, (byte) 0xFB
        };
         public final byte[] sim_privexp = new byte[]{

        (byte) 0x5C, (byte) 0xC9, (byte) 0x0C, (byte) 0x14, (byte) 0xDC, (byte) 0xB6, (byte) 0x6C, (byte) 0x2C, 
        (byte) 0xBE, (byte) 0x84, (byte) 0xDA, (byte) 0x54, (byte) 0xFD, (byte) 0xCA, (byte) 0x38, (byte) 0x6F, 
        (byte) 0xF6, (byte) 0x2A, (byte) 0xE7, (byte) 0xB3, (byte) 0xC7, (byte) 0x94, (byte) 0x78, (byte) 0x44, 
        (byte) 0x94, (byte) 0xC4, (byte) 0xFE, (byte) 0x1A, (byte) 0xFC, (byte) 0xD5, (byte) 0x10, (byte) 0xCF, 
        (byte) 0x1D, (byte) 0x21, (byte) 0xB4, (byte) 0x41, (byte) 0x3C, (byte) 0x37, (byte) 0x01, (byte) 0x7A, 
        (byte) 0xE9, (byte) 0x70, (byte) 0x9E, (byte) 0x03, (byte) 0xEC, (byte) 0x75, (byte) 0x8C, (byte) 0x1A, 
        (byte) 0x46, (byte) 0x28, (byte) 0xFA, (byte) 0xC3, (byte) 0x8A, (byte) 0x81, (byte) 0xCD, (byte) 0x1F, 
        (byte) 0x30, (byte) 0x54, (byte) 0x37, (byte) 0x67, (byte) 0x54, (byte) 0x07, (byte) 0xD4, (byte) 0x87, 
        (byte) 0x32, (byte) 0x43, (byte) 0x1D, (byte) 0x86, (byte) 0x15, (byte) 0x0E, (byte) 0xF0, (byte) 0x5C, 
        (byte) 0xAC, (byte) 0xBC, (byte) 0x41, (byte) 0xA7, (byte) 0x3C, (byte) 0x5E, (byte) 0x4B, (byte) 0x39, 
        (byte) 0xC3, (byte) 0x5E, (byte) 0xE0, (byte) 0x45, (byte) 0x34, (byte) 0xAD, (byte) 0x6C, (byte) 0x40,
        (byte) 0x14, (byte) 0xBF, (byte) 0x11, (byte) 0xEB, (byte) 0x2B, (byte) 0x64, (byte) 0x65, (byte) 0x77,
        (byte) 0xEA, (byte) 0xA3, (byte) 0x95, (byte) 0xBE, (byte) 0xDA, (byte) 0x0B, (byte) 0x0D, (byte) 0x1B, 
        (byte) 0xC2, (byte) 0x07, (byte) 0x2D, (byte) 0x26, (byte) 0xB9, (byte) 0x8C, (byte) 0xF1, (byte) 0x77, 
        (byte) 0x9D, (byte) 0xD8, (byte) 0xC9, (byte) 0xD9, (byte) 0xA4, (byte) 0xFA, (byte) 0x85, (byte) 0x61, 
        (byte) 0x28, (byte) 0xE4, (byte) 0x44, (byte) 0x41, (byte) 0x48, (byte) 0x98, (byte) 0xBA, (byte) 0xF9
         };
                 
                 /** Returns the 2 byte AIP (Application Interchange Profile) 
	 *  See Book 3, Annex C1 for details
	 *   */
	public short getAIP() {
		return 0x5800;
		// 4000 SDA supported
		// 1000 Cardholder verification supported
		// 0800 Terminal risk management is to be performed
	}
	
	private final byte[] fci = new byte[]{
			0x6F, // FCI Template 
			0x25, // Length
			(byte)0x84, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x04, (byte)0x80, 0x02, // Dedicated File name 
			(byte)0xA5, 0x1A, // File Control Information Proprietary Template
				0x50, 0x0E, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x41, 0x75, 0x74, // Application Label  
				(byte)0x87, 0x01, 0x00, // Application Priority Indicator 
				0x5F, 0x2D, 0x04, 0x6E, 0x6C, 0x65, 0x6E // Language Preference
			};

	// File for EMV-CAP
	private final byte[] record1 = new byte[]{	
			0x70, // Read record message template
			0x00, // Record length
			(byte)0x8C, 0x21, (byte)0x9F, 0x02, 0x06, (byte)0x9F, 0x03, 0x06, (byte)0x9F, 0x1A, 0x02, (byte)0x95, 0x05, 0x5F, 0x2A, 0x02, (byte)0x9A, 0x03, (byte)0x9C, 0x01, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x35, 0x01, (byte)0x9F, 0x45, 0x02, (byte)0x9F, 0x4C, 0x08, (byte)0x9F, 0x34, 0x03, // Card Risk Management Data Object List 1 
			(byte)0x8D, 0x0C, (byte)0x91, 0x0A, (byte)0x8A, 0x02, (byte)0x95, 0x05, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x4C, 0x08, // Card Risk Management Data Object List 2
			0x5A, 0x05, 0x12, 0x34, 0x56, 0x78, (byte)0x90, // 5A Primary account number			
			0x5F, 0x34, 0x01, 0x02, // Bank identifier code
			(byte)0x8E, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Cardholder Verification Method (CVM) List (Always transaction_data PIN performed by ICC) 
			(byte)0x9F, 0x55, 0x01, (byte)0x80, // Unknown field
			(byte)0x9F, 0x56, 0x0C, 0x00, 0x00, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Bit filter
			};
 	
	/*
	// File for EMV
	private final byte[] record1 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length
			// Mandatory data objects
			0x5F, 0x24, 0x03, // Application Expiry Date
			0x5A, 0x05, 0x12, 0x34, 0x56, 0x78, (byte)0x90, // 5A Primary account number
			(byte)0x8C, 0x21, (byte)0x9F, 0x02, 0x06, (byte)0x9F, 0x03, 0x06, (byte)0x9F, 0x1A, 0x02, (byte)0x95, 0x05, 0x5F, 0x2A, 0x02, (byte)0x9A, 0x03, (byte)0x9C, 0x01, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x35, 0x01, (byte)0x9F, 0x45, 0x02, (byte)0x9F, 0x4C, 0x08, (byte)0x9F, 0x34, 0x03, // Card Risk Management Data Object List 1
			(byte)0x8D, 0x18, (byte)0x91, 0x0A, (byte)0x8A, 0x02, (byte)0x95, 0x05, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x4C, 0x08, // Card Risk Management Data Object List 2
			// Other data
			(byte)0x8E, 0x02, 0x01, 0x00, // Cardholder Verification Method (CVM) List (Always transaction_data PIN performed by ICC)
			(byte)0x9F, 0x4A, 0x01, (byte)0x82, // Static Data Authentication Tag List
			};
 	*/
	
	private final byte[] record2 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length			
			// Data required for DDA/CDA
			(byte)0x8F, 0x00, // Certification Authority Public Key Index
			(byte)0x90, 0x00, // Issuer Public Key Certificate
			(byte)0x92, 0x00, // Issuer Public Key Remainder
			(byte)0x9F, 0x32, 0x00, // Issuer Public Key Exponent
			};
	
	private final byte[] record3 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length			
			// Data required for DDA/CDA (continued)
			(byte)0x9F, 0x46, 0x00, // ICC Public Key Certificate
			(byte)0x9F, 0x47, 0x00, // ICC Public Key Exponent
			(byte)0x9F, 0x48, 0x00, // ICC Public Key Remainder
			(byte)0x9F, 0x49, 0x03, (byte)0x9F, 0x37, 0x04, // Dynamic Data Authentication Data Object List (DDOL)
			};
	
	/** Return the length of the data specified in the CDOL1 
	 * 
	 */
	public short getCDOL1DataLength() {
		return 0x2B;
		//return 43;
	}

	/** Return the length of the data specified in the CDOL2 
	 * 
	 */
	public short getCDOL2DataLength() {
		return 0x1D;
		//return 29;
	}
	
	public byte[] getFCI() {
		return fci;
	}

	public short getFCILength() {
		return (short)fci.length;
	}
	
	/** Provide the response to INS_READ_RECORD in the response buffer
	 * 
	 */
	public void readRecord(byte[] apduBuffer, byte[] response){
		if(apduBuffer[OFFSET_P2] == 0x0C && apduBuffer[OFFSET_P1] == 0x01) 
		{ // SFI 1, Record 1
			Util.arrayCopyNonAtomic(record1, (short)0, response, (short)0, (short)record1.length);
			response[1] = (byte)(record1.length - 2); 
		}
		else if(apduBuffer[OFFSET_P2] == 0x0C && apduBuffer[OFFSET_P1] == 0x02) 
		{ // SFI 1, Record 2
			Util.arrayCopyNonAtomic(record2, (short)0, response, (short)0, (short)record2.length);
			response[1] = (byte)(record2.length - 2); 
		}
		else if(apduBuffer[OFFSET_P2] == 0x0C && apduBuffer[OFFSET_P1] == 0x03) 
		{ // SFI 1, Record 3
			Util.arrayCopyNonAtomic(record3, (short)0, response, (short)0, (short)record3.length);
			response[1] = (byte)(record3.length - 2); 
		}
		else {
			// File does not exist
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
	}
	

}
