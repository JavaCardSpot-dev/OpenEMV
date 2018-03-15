ℹ️ IMPORTANT: This repository is used for class PV204 Security Technologies at Masaryk University. All meaningful improvements will be attempted to be pushed to upstream repository in June 2018

[![Build Status](https://travis-ci.org/JavaCardSpot-dev/OpenEMV.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/OpenEMV)

# (Original source link : https://github.com/JavaCardOS/OpenEMV)

# OpenEMV Introduction

The OpenEMV is a Java Card implementation of the EMV standard. 

(a) Project has a very basic Europay, MasterCard, Visa (EMV) applet supporting only Static Data Authentication (SDA) and plaintext offline PIN. It does not offer personalisation support. PIN and other relevent requisites are Hard-coded in the project.

(b) SimpleEMVApplet class does the central processing of APDUs. 

(c) Handling of all crypto-related stuff is outsourced to java class EMVCrypro

(d) Handling of the static card data to the java class EMVStaticData

(e) Handling of the EMV protocol and session state to java class EMVProtocolState

# Contents of the repository

(a)	applet/src/main/java/applet: Contains the requisite five files source code files: SimpleEMVApplet.java, EMVStaticData.java
, EMVProtocolState.java, EMVCrypto.java, EMVConstants.java

(b) libs-sdks: Provides Sun/Oracle JavaCard SDK binaries

(c) applet/build.gradle. Buildscript configuration for the javacard-gradle plugin

# Description of Java classes
SimpleEMVApplet.java
 
 Basic EMV applet supporting only SDA and plaintext offline PIN. 

EMVConstants.java
  
  EMVConstants defines a constants used in the EMV standard and constants specific to this implementation. It extends ISO7816
  as some ISO7816 constants are also used by EMV.
 
EMVStaticData.java
 
 Class to record all the static data of an EMV applet ie. the card details that do not change over time (such as PAN, expiry date, etc.), with the exception of the cryptographic keys.
  
EMVProtocolState.java
 
 Class to track the transient - ie. "session" - state of the EMV protocol, as well as the persistent state. 
 
EMVCrypto.java

 An object of this class is responsible for all crypto-related stuff. It provides methods for computing Applications Cryptograms and
 contains all the cryptographic keys needed for this.  

# Build and installation instructions

# Pre-requisites (Dependencies)

(a) Netbeans 8.2 and above

(b) ant tool version 1.9.10

(c) GP tool version 0.2 for interfacing with card reader

(d) Only necessary binary content, usable with ant-javacard. https://github.com/JavaCardSpot-dev/OpenEMV/tree/master/libs-sdks

# Building cap file

(a) ant -f jcbuild.xml build    - It will create .cap file from .jar file taking parameters from jcbuild.xml

# Installing cap file

(a) gp -list -d  // To view the list of applets on javacard
 
(b) gp -install OpenEMV.cap -d   // To install a java applet on card

# Usage

There are two ways to use this project.

(a) Use pyApduTool to Download this OpenEMV CAP file to card and install it, select the applet and send APDU to card.

(b) Project can be build in Netbeans 8.2 using JDK 1.8 as well in JCIDE .

# Testing

***********************************************************************************************

APDU packet for Testing Response from Applet

00 A4 04 00 00

response = 6F258407A0000000048002A51A500E536563757265436F6465204175748701005F2D046E6C656E

***********************************************************************************************

# License 

The source code is released under LGPL and is free.

