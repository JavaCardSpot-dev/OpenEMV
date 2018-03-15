ℹ️ IMPORTANT: This repository is used for class PV204 Security Technologies at Masaryk University. All meaningful improvements will be attempted to be pushed to upstream repository in June 2018

[![Build Status](https://travis-ci.org/JavaCardSpot-dev/OpenEMV.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/OpenEMV)

# OpenEMV Introduction
The OpenEMV is a Java Card implementation of the EMV standard. 
(a) Project has a very basic EMV applet supporting only SDA and plaintext offline PIN.
(b) It does not offer personalisation support - everything is hard-coded.
(c) The code is optimised for readability, and not for performance or memory use.
(d) SimpleEMVApplet class does the central processing of APDUs. 
(e) handling of all crypto-related stuff is outsourced to java class EMVCrypro
(f) handling of the static card data to the java class EMVStaticData
(g) handling of the EMV protocol and session state to java class EMVProtocolState

# Contents of the repository
(a)	applet/src/main/java/applet: Contains the requisite five files source code files :  SimpleEMVApplet.java, EMVStaticData.java
, EMVProtocolState.java, EMVCrypto.java, EMVConstants.java
(b) libs-sdks: Provides Sun/Oracle JavaCard SDK binaries
(c) applet/build.gradle. Buildscript configuration for the javacard-gradle plugin

# Description of Java classes
SimpleEMVApplet.java
 A very basic EMV applet supporting only SDA and plaintext offline PIN.
 This applet does not offer personalisation support - everything is hard-coded.
 The code is optimised for readability, and not for performance or memory use.
 This class does the central processing of APDUs. Handling of all crypto-related
 stuff is outsourced to EMVCrypro, handling of the static card data to EMVStaticData and handling of the EMV protocol and session state to EMVProtocolState.


EMVConstants.java
  EMVConstants defines a constants used in the EMV standard and 
  constants specific to this implementation. It extends ISO7816
  as some ISO7816 constants are also used by EMV.
 
EMVStaticData.java
 Class to record all the static data of an EMV applet, ie. the card details that
 do not change over time (such as PAN, expiry date, etc.), with the exception
 of the cryptographic keys.
 This static data is organised in the simplest possible way, using some public byte
 arrays to record exact APDUs that the card has to produce.
 This class does not offer personalisation support - everything is hard-coded.
  
EMVProtocolState.java
 Class to track the transient - ie. "session" - state of the EMV protocol,
 as well as the persistent state.
 
 This implementation is not secure in that it allows the ATC to overflow.
 Also, it does not offer any support for blocking the card.
 
EMVCrypto.java
 An object of this class is responsible for all crypto-related stuff.
 It provides methods for computing Applications Cryptograms and
 contains all the cryptographic keys needed for this.
 One  design choice is whether the client passes the ATC (and maybe other data)
 explicitly as parameters, or whether this object obtain them from the applet as needed.
 We go for the latter approach. The former leads to a 'cleaner' interface, but with many
 more parameters.
 

# Usage
There are two ways to use this project.
(a) Use pyApduTool to Download this OpenEMV CAP file to card and install it, select the applet and send APDU to card.
(b) Project can be build in Netbeans as well in JCIDE project directly to view and edit the source code.

# Testing

***********************************************************************************************
APDU packet for Testing Response from Applet

00 A4 04 00 00

response = 6F258407A0000000048002A51A500E536563757265436F6465204175748701005F2D046E6C656E
***********************************************************************************************

# Building
Using [JCIDE](http://javacardos.com/javacardforum/viewtopic.php?f=26&t=43?ws=github&prj=OpenEMV) open this project,  Click "Buid All Packages(F7)" to build the source code.

# License 
The source code is released under LGPL and is free.

