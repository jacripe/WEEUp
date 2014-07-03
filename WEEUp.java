/* HEADER
 */

/* ***************************************************************
 * 			INCLUDES
 * ***************************************************************/
import java.io.*;
import java.net.*;
import java.math.*;
import java.util.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

/* ***************************************************************
 * 			CLASS DEFINITION
 * ***************************************************************/

public class WEEUp {
//***************************************************************
//			DATA MEMBERS
	private enum State { LOGIN, MAIN, PROFILE, TRANSFER };

	private static int	nV = 1; //Verbosity Level

	private int		nPort;
	private String		sHostName;
	private String		sStringBuffer;
	private String		sLineBuffer;
	private String		sUser = "";
	private String		sCWD = System.getProperty("user.dir");
	private String		sFS = System.getProperty("file.separator");

	private Socket		mSocket;
	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;

	private InputStream	mRawInStream;
	private OutputStream	mRawOutStream;

	private DataInputStream		mDInStream;
	private DataOutputStream	mDOutStream;
	
	private Console			mConsole = System.console();

	private static boolean		bEncrypt = false;	//Encrypted or Plain
	private static int		nKeyLen = 1024;		//Key Length
	private static String		sProtocol = "SKIP";	//SKIP or Generated
	private static String		sCipher = "DES";	//Shared Cipher Algorithm

	private static byte[]		aKeyBytes;	//Shared Secret Key Byte Array
	private static DHPrivateKey	mDHPrivKey;	//Private Client DH Key Object
	private static DHPublicKey	mServerPubKey;	//Public Server DH Key
	private static SecretKey	mKey;		//Shared Secret Key Object
	private static Cipher		mECipher;	//Cipher Object for Ecnryption
	private static Cipher		mDCipher;	//Cipher Object for Decryption

	private static final int	nPrimeCert = 0;	//Certainty of Prime Number

	private static SecureRandom	mSecRan = new SecureRandom();

//**************************************************************
//			MAIN

	public static void main(String[] args) {
		log("WEEUp Client Started");
		WEEUp w = parseArgs(args);
		w.loadUserConf();
		w.createSocket();
		log("Starting Input Loop");
		while(true) {
			w.doShit();
		} //END Main Loop
	} //END main(args)


//**************************************************************
//			FUNCTIONS
//------------------
//	Constructors
	WEEUp() {
		if(nV > 1) log("new WEEUp()");
		nPort = 4321;
		sHostName = "localhost";
	} //END WEEUp()

	WEEUp(int p) {
		if(nV > 1) log("new WEEUp(" + p + ")");
		nPort = p;
		sHostName = "localhost";
	} //END WEEUp(int)

	WEEUp(int p, String h) {
		if(nV > 1) log("new WEEUp(" + p + ", " + h + ")");
		nPort = p;
		sHostName = h;
	} //END WEEUp(int, String)
	
//------------------
//	Initializers
	public static WEEUp parseArgs(String[] a) {
		String msg = "Parsing Arguments:";
		for(String s: a) msg += "\t" + s;

		WEEUp retVal = null;
		//Check Number of Arguments...
		switch(a.length) {
		case 0:
			if(nV > 1) log("No arguments. Using default constructor");
			break;
		case 1:
			retVal = new WEEUp(Integer.parseInt(a[0]));
			break;
		case 2:
			retVal = new WEEUp(Integer.parseInt(a[0]), a[1]);
			break;
		case 3:
			retVal = new WEEUp(Integer.parseInt(a[0]), a[1]);
			retVal.nV = Integer.parseInt(a[2]);
		default:
			if(nV > 1) log("Too many arguments");
			printUsage();
			if(nV > 1) log("Using default constructor");
			break;
		} //END Switch Number of Arguments
		if(retVal == null)
			retVal = new WEEUp();
		//END If No Constructor Called
		return retVal;
	} //END parseArgs(String[])

	public void loadUserConf() {
		log("Loading User Configuration...");
		try {
			File f = new File(".wupconf");
			//If the file does not exist...
			if(!f.isFile() || !f.canRead()) {
				//...make a new one
				log("Writing new configuration file");
				FileWriter fOut = new FileWriter(f);
				fOut.write("alg=DES\n" +
					   "len=1024\n" +
					   "pro=SKIP\n");
				fOut.flush();
				fOut.close();
				return;
			} //END File NOT Avail

			//Otherwise, read it
			BufferedReader fIn = new BufferedReader(new FileReader(f));
			String line = fIn.readLine();

			//While we have a line...
			while(line != null) {
				//...parse it
				//FORMAT:
				//key=value
				//...
				String[] vals = line.split("=");
				//...check it
				if(vals[0].equals("alg"))
					sCipher = vals[1];
				else if(vals[0].equals("len"))
					nKeyLen = (new Integer(vals[1])).intValue();
				else if(vals[0].equals("pro"))
					sProtocol = vals[1];
				else if(vals[0].equals("pro"))
					sProtocol = vals[1];
				else
					log("Unknown value in configuration file: " + line);
				//...go to the next
				line = fIn.readLine();
			} //END While Line NOT NULL
		} catch(Exception e) {
			log("ERROR: " + e.toString());
		} //END Try/Catch
	} //END loadUserConf()

	public void createSocket() {
		log("Connecting to server...");
		try {
			mSocket = new Socket(sHostName, nPort);
			if(nV > 1) log("Created Socket");

			mRawInStream = mSocket.getInputStream();
			mDInStream = new DataInputStream(mRawInStream);
			mInputStream = new BufferedReader(
					new InputStreamReader(
					mRawInStream));
			if(nV > 1) log("Created Input Streams");

			mRawOutStream = mSocket.getOutputStream();
			mDOutStream = new DataOutputStream(mRawOutStream);
			mOutputStream = new PrintWriter(mRawOutStream, true);
			if(nV > 1) log("Created Output Stream");

			sLineBuffer = sStringBuffer = null;
			bEncrypt = false;
			log("Buffers Initialized");

			if(!initEncryption())
				throw new Exception("Encryption Initialization Failed");
			log("Encryption Initialized");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
	} //END createSocket()
	
	//Adapted from Oracle documentation:
	//http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
	private boolean initEncryption() {
		if(nV > 1) log("Initializing Encryption...");
		try {
			if(nV > 1) log("Waiting on Key Data From Server...");
			byte[] serverPubKeyBytes = receiveBytes();

			//Instantiate DH Public Key From Bytes
			KeyFactory kFac = KeyFactory.getInstance("DiffieHellman");
			if(nV > 1) log("Initialized Key Factory");
			X509EncodedKeySpec encKSpec =
				new X509EncodedKeySpec(serverPubKeyBytes);
			DHPublicKey mServerKey = (DHPublicKey) kFac.generatePublic(encKSpec);
			if(nV > 1) log("Instantiated Server Public Key");

			//Initialize Key Specifications
			DHParameterSpec kParmSpec = mServerKey.getParams();

			//Generate Client Keys
			KeyPairGenerator kPGen = KeyPairGenerator.getInstance("DiffieHellman");
			kPGen.initialize(kParmSpec);
			KeyPair keyPair = kPGen.generateKeyPair();
			if(nV > 1) log("Generated Client DH Public/Private Key Pair");

			//Initialize Key Agreement
			KeyAgreement kAgree = KeyAgreement.getInstance("DiffieHellman");
			kAgree.init(keyPair.getPrivate());
			if(nV > 1) log("Initialized Client Key Agreement");

			//Encode Public Key For Transport
			byte[] pubKeyBytes = keyPair.getPublic().getEncoded();
			if(nV > 1) log("Encoded Public Key:\n" + toHexString(pubKeyBytes));

			//Send Notification to Server
			send("[RECEIVED]");
			//Send Client Public Key to Server
			sendBytes(pubKeyBytes);
			if(nV > 1) log("Sent Encoded Public Key to Server");

			//Get Confirmation & Secret Key Length From Server
			//FORMAT:
			//[PRIVKEY]
			//Secret Key Length
			//[RECEIVED]
			//[END]
			if(nV > 1) log("Waiting on Server Response");
			receive();
			if(!sStringBuffer.contains("[RECEIVED]"))
				throw new Exception("Error Sending Public Key to Server");
			if(nV > 1) log("Received Server Response:\n" + sStringBuffer);

			//Agree Those Keys
			kAgree.doPhase(mServerKey, true);
			if(nV > 1) log("Client Key Agreement Complete");

			//Generate Symmetric Client Secret Key (Should Match Server)
			if(!sStringBuffer.contains("[PRIVKEY]"))
				throw new Exception("Error Receiving Secret Key Length From Server");
			int length = new Integer(sStringBuffer.split("\n")[1]).intValue();
			aKeyBytes = new byte[length];
			length = kAgree.generateSecret(aKeyBytes, 0);
			if(nV > 1) log("Generated Client Secret Key Bytes:\n" + toHexString(aKeyBytes));

			//Notify Server
			send("[CIPHER]\n" + sCipher + "\n[SUCCESS]");
			
			//Generate Symetric Secret Key & Cipher Objects from Bytes
			kAgree.doPhase(mServerKey, true);
			mKey = kAgree.generateSecret(sCipher);
			mECipher = Cipher.getInstance(sCipher);
			mECipher.init(Cipher.ENCRYPT_MODE, mKey);
			mDCipher = Cipher.getInstance(sCipher);
			mDCipher.init(Cipher.DECRYPT_MODE, mKey);
			bEncrypt = true;
			if(nV > 1) log("Generated Client Secret Key & Cipher Objects Using "
			   + sCipher + " Algorithm");

			//Get Server Confirmation to Verify En/Decryption is functional
			if(nV > 1) log("Waiting on Server Encryption Verification Test...");
			receive();
			if(!sStringBuffer.contains("[VERIFY_ENCRYPTION]"))
				throw new Exception("Bad Server Encryption Test");
			send("[SUCCESS]");

			if(nV > 1) log("Waiting on Server Confirmation...");
			receive();
			if(!sStringBuffer.contains("[SUCCESS]"))
				throw new Exception("Encryption Verification Failed");
			if(nV > 1) log("SUCCESS! ENCRYPTION IS LIVE!");
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return true;
	} //END initEncryption()

//--------------------
//	Menu Functions
	public void doShit() {
		if(nV > 1) log("Time to do something...");
		System.out.println("=====================");
		//Get Server Input...
		receive();
		//Parse Input...
		String[] strArray = sStringBuffer.split("\n");
		//For Each Line...
		for(int i = 0; i < strArray.length; i++) {
			//...instantiate a variable
			String s = strArray[i];
			//...check if it's a command
			if(s.equals("[RECEIVED]")) {
				if(nV > 1) log("Server Received Last Message");
			} else if(s.equals("[SUCCESS]")) {
				if(nV > 1) log("Transaction Successful");
			} else if(s.equals("[FAILED]")) {
				if(nV > 1) log("Failed Transaction");
			} else if(s.equals("[START]")) {
				start();
			} else if(s.equals("[CREATE]")) {
				create();
			} else if(s.equals("[LOGIN]")) {
				login();
			} else if(s.equals("[MAIN]")) {
				mainMenu();
			} else if(s.equals("[PROFILE]")) {
				profile();
			} else if(s.equals("[TRANSFER]")) {
				transfer();
			} else if(s.equals("[UNKNOWN]")) {
				errorOut("ERROR: Server in Unknown State",
					new Exception("Unknown Server State"));
			} //...otherwise...
			else if(s != null) {
				//...display the line to user
				System.out.println(s);
			} //END If/Else Line
		} //END For Each Line
	} //END doShit()

	private void start() {
		if(nV > 1) log("Start Menu...");
		//While we haven't succeeded yet...
		boolean failed = true;
		while(failed) {
			//...prompt the user
			System.out.print("Please enter your choice (C/L)\n: ");
			//...retrieve & verify user input
			sLineBuffer = mConsole.readLine();
			if(sLineBuffer == null || sLineBuffer.isEmpty()) {
				System.out.println("Invalid Input");
				continue;
			} //END If Input NULL
			//...parse it
			char choice = sLineBuffer.toLowerCase().charAt(0);
			if(nV > 1) log("Received User Input: " + sLineBuffer);
			//If User Enterred Unavailable Choice
			if(choice != 'c' && choice != 'l') {
				//Try again
				System.out.println("Invalid Input!\nPlease try \"C\" or \"L\"...\n");
				failed = true;
			} else { //Otherwise...
				//Send it & continue program
				if(choice == 'c') send("[CREATE]");
				else if(choice == 'l') send("[LOGIN]");
				//What the hell happened here?
				else {
					Exception e = new Exception("Unknown User Input "
								   + "(" + choice + ") "
								   + sLineBuffer);
					errorOut(e.toString(), e);
				} //END If/Else Choice Create/Login/Other
				failed = false;
			} //END If/Else (Valid Chocie)
		} //END while
	} //END start()

	private void create() {
		if(nV > 1) log("Creating a new user...");
		//While we haven't succeeded...
		boolean failed = true;
		while(failed) {
			//...get the user name
			System.out.print("Enter New Username: ");
			String user = mConsole.readLine();
			if(user == null || user.isEmpty())
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			//END If User NULL
			user = user.toLowerCase();
			if(nV > 1) log("Received User: " + user);
			//...notify server
			send(user);
			receive();
			//...get the password hash twice
			if(nV > 1) log("Received Server Response: " + sStringBuffer);
			if(!sStringBuffer.contains("[RECEIVED]")) {
				System.out.println("Bad Username. Plese try again...");
				continue;
			} //END If Not RECEIVED
			//TODO Use char array instead of string for password/hash
			System.out.print("Enter New Password: ");
			String pass = new String(mConsole.readPassword());
			if(pass == null || pass.isEmpty()) {
				System.out.println("Please enter a valid password");
				continue;
			} //END If Pass NULL
			String hash = md5(pass + ":" + user);
			if(nV > 1) log("Received Hash: " + hash);
			System.out.print("Re-enter Password: ");
			pass = new String(mConsole.readPassword());
			if(pass == null || pass.isEmpty())
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			String hash2 = md5(pass + ":" + user);
			if(nV > 1) log("Received Hash: " + hash2);
			//...make sure they match
			if(!hash.equals(hash2)) {
				System.out.println("Invalid Input!\nPasswords do not match.");
				send("[FAILED]");
				failed = true;
				continue;
			} //END If Hash1 NOT Hash2
			//...notify server
			send(hash2);

			//...check server response
			receive();
			if(nV > 1) log("Received Server Response: " + sStringBuffer);
			if(sStringBuffer.contains("[SUCCESS]")) {
				System.out.println("New Account Created!\n"
				+ "User: " + user + "\n"
				+ "Pass: " + pass);
				failed = false;
			} else {
				System.out.println("Error! Account Creation Failed.\nPlease try again");
				failed = true;
			} //END If/Else SUCCESS
		} //END while
	} //END create()

	private void login() {
		if(nV > 1) log("Beginning login...");
		//While we have attempts remaining & haven't succeeded...
		int failedLogins = 0;
		while(failedLogins < 3 && failedLogins >= 0) {
			//...get the user name
			System.out.print("Enter User Name\n: ");
			String user = mConsole.readLine();
			if(user == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			if(nV > 1) log("Received User: " + user);
			//...notify server
			send(user);
			receive();
			if(nV > 1) log("Received Server Response: " + sStringBuffer);
			if(!sStringBuffer.contains("[RECEIVED]")) {
				Exception e = new Exception("Error sending login user to server");
				errorOut(e.toString(), e);
			}  //END NOT RECEIVED

			//...get the password hash
			System.out.print("Enter Password\n: ");
			String hash = new String(mConsole.readPassword());
			//TODO String hash = md5(mConsole.readPassword());
			if(hash == null) {
				System.out.println("Please enter a valid username & password");
				continue;
			} //END If Hash NULL
			hash = md5(hash + ":" + user);
			if(nV > 1) log("Received Hash: " + hash);
			//...notify server
			send(hash);
			receive();
			if(nV > 1) log("Received Server Response: " + sStringBuffer);
			if(sStringBuffer.contains("[SUCCESS]")) {
				log("Successful Login!");
				sUser = user;
				failedLogins = -1;
			} else {
				System.out.println("Login Failed...");
				failedLogins++;
				log("Failed " + failedLogins + "/3 Login Attempts");
			} //END If/Else SUCCESS
			if(failedLogins >= 3)
				errorOut("Failed Login Attempt",
					new Exception("Invalid Credentials"));
			//END If Out of Login Attempts
		} //END While Failed & Attempts Remaining
	} //END login()

	private void mainMenu() {
		if(nV > 1) log("Main Menu...");
		try {
			//Initialize Buffer
			char choice = 'z';
			//While We Don't Have a Valid Selection...
			boolean badInput = true;
			while(badInput) {
				//...prompt User
				System.out.print("Enter Your Choice (M/P/T/Q/H)\n: ");
				//...get input
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null || sLineBuffer.isEmpty()) {
					if(nV > 1) log("NULL Input Received");
					System.out.println("Please make a valid selection");
					continue;
				} else {
					sLineBuffer = sLineBuffer.toLowerCase();
					choice = sLineBuffer.charAt(0);	
				} //END If/Else Input NULL

				//...process input
				if(choice == 'q')
					quit();
				else if(choice == 'h')
					help();
				else if(choice == 'm' || choice == 'p' || choice == 't') {
					badInput = false;
					if(choice == 'm')
						send("[MAIN]");
					else if(choice == 'p')
						send("[PROFILE]");
					else if(choice == 't')
						send("[TRANSFER]");
					else
						if(nV > 1) log("Unknown Selection: (" + choice + ") "
						   + sLineBuffer);
					//END If/Else Choice M/P/T/Other
				} else {
					System.out.println("Sorry, invalid input.\n"
					+ "Please try: (M)ain Menu, (P)rofile, (T)ransfer, "
					+ "(H)elp or (Q)uit");
				}//END If/Else Choice Q/H/Other
			} //END While Bad Input
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
	} //END mainMenu()

	private void profile() {
		if(nV > 1) log("User Profile...");
		try {
			//Initialize Buffer
			char choice = 'z';
			//While we don't have a valid selection...
			boolean badInput = true;
			while(badInput) {
				//...prompt user
				System.out.print("Enter Your Choice (R/C/T/M/H/Q)\n: ");
				//...get input
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null || sLineBuffer.isEmpty()) {
					if(nV > 1) log("NULL Input Received");
					System.out.println("Please make a valid selection");
					continue;
				} else {
					sLineBuffer = sLineBuffer.toLowerCase();
					choice = sLineBuffer.charAt(0);
				} //END If/Else Input NULL

				//...process input
				if(choice == 'q')
					quit();
				else if(choice == 'h')
					help();
				else if(choice == 'm' || choice == 'r' ||
					choice == 'c' || choice == 't') {
					badInput = false;
					switch(choice) {
					case 'q': quit(); break;
					case 'h': help(); break;
					case 'm': send("[MAIN]"); break;
					case 'r': send("[RESET]"); resetPassword(); break;
					case 'c': send("[CONF]"); configure(); break;
					case 't': send("[TRANSFER]"); break;
					default:
					} //END Switch Choice
				} else {
					badInput = true;
					System.out.println("Sorry, invalid selection.\n"
					+ "Please try:\n"
					+ "\t(R)eset, (T)ransfer, (M)ain\n"
					+ "\t(H)elp or (Q)uit");
				} //END If/Else Choice
			} //END While Bad Input
		} catch(Exception e) {
			errorOut("ERROR: " + e.toString(), e);
		} //END Try/Catch
	} //END profile()

	private void transfer() {
		if(nV > 1) log("File Transfer...");
		try {
			//Initiliaze Buffer
			char choice = 'z';
			//While we do not have a valid selection...
			boolean badInput = true;
			while(badInput) {
				//...prompt user
				System.out.print("Enter Your Choice (L/U/D/P/M/H/Q)\n: ");
				//...get input
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null || sLineBuffer.isEmpty()) {
					if(nV > 1) log("NULL User Input");
					System.out.println("Please make a valid selection");
					continue;
				} else {
					sLineBuffer = sLineBuffer.toLowerCase();
					choice = sLineBuffer.charAt(0);
				} //END If/Else Input NULL

				//...process input
				if(choice == 'q')
					quit();
				else if(choice == 'h')
					help();
				else if(choice == 'l' || choice == 'r' ||
					choice == 'u' || choice == 'd' ||
					choice == 'p' || choice == 'm' ||
					choice == 'h' || choice == 'q') {
					badInput = false;
					switch(choice) {
					case 'm': send("[MAIN]"); break;
					case 'l':
						//Notify Server...
						send("[LIST]");
						//Receive File List
						//FORMAT:
						//Doc Root: ...
						//File List:
						//File 1
						//...
						//File n
						//[LIST]
						//[END]
						sStringBuffer = receive();
						if(sStringBuffer == null)
							throw new Exception("Empty File List");
						else if(!sStringBuffer.contains("[LIST]"))
							throw new Exception("Invalid File List");
						else {
							System.out.println("=====================");
							String[] files = sStringBuffer.split("\n");
							for(int i = 0; i <= files.length-2; i++)
								System.out.println(files[i]);
						} //END If/Else LIST
						break;
					case 'r': send("[REMOVE]"); remove(); break;
					case 'u': send("[UPLOAD]"); upload(); break;
					case 'd': send("[DOWNLOAD]"); download(); break;
					case 'p': send("[PROFILE]"); break;
					} //END Switch Choice
				} else 
					System.out.println("Sorry, invalid selection.\n"
					+ "Please try: (L)ist Files, (U)pload File, "
					+ "(M)ain Menu, (P)rofile, (H)elp or (Q)uit");
				//END If/Else Choice
			} //END While Bad Input
		} catch(Exception e) {
			errorOut("ERROR: " + e.toString(), e);
		} //END Try/Catch
	} //END transfer()

//---------------------------
//	Operational Functions
	private void resetPassword() {
		boolean failed = true;
		while(failed) {
			//...get the password hash twice
			//TODO Use char array instead of string for password/hash
			System.out.print("Enter New Password: ");
			String pass = new String(mConsole.readPassword());
			if(pass == null || pass.isEmpty()) {
			        System.out.println("Please enter a valid password");
			        continue;
			} //END If Pass NULL
			String hash = md5(pass + ":" + sUser);
			if(nV > 1) log("Received Hash: " + hash);
			System.out.print("Re-enter Password: ");
			pass = new String(mConsole.readPassword());
			if(pass == null || pass.isEmpty())
			        errorOut("Received NULL Input",
			                new Exception("Null User Input"));
			String hash2 = md5(pass + ":" + sUser);
			if(nV > 1) log("Received Hash: " + hash2);
			//...make sure they match
			if(!hash.equals(hash2)) {
			        System.out.println("Invalid Input!\nPasswords do not match.");
			        send("[FAILED]");
			        failed = true;
			        continue;
			} //END If Hash1 NOT Hash2
			//...notify server
			send(hash2);
			
			//...check server response
			receive();
			if(nV > 1) log("Received Server Response:\n" + sStringBuffer);
			if(sStringBuffer.contains("[SUCCESS]")) {
			        System.out.println("Password Reset!\n"
			        + "User: " + sUser + "\n"
			        + "Pass: " + pass);
			        failed = false;
			} else {
			        System.out.println("Error! Account Creation Failed.\nPlease try again");
			        failed = true;
			} //END If/Else SUCCESS
		} //END while
	} //END resetPassword()

	public boolean configure() {
		log("Configuring settings...");
		try {
			System.out.println("\tSettings\n" +
					 "-----------------\n" + 
					 "(C)ipher  : " + sCipher + "\n" +
					 "(L)ength  : " + nKeyLen + "\n" +
					 "(P)rotocol: " + sProtocol + "\n\n" +
					 "What would you like to change?");
			boolean badInput = true;
			while(badInput) {
				System.out.print(": ");
				String input = mConsole.readLine();
				if(input == null || input.isEmpty()) {
					System.out.println("Please make a selection (C/L/P)");
					badInput = true;
					continue;
				} //END If Input NULL
				input = input.toLowerCase();
				char c = input.charAt(0);
				if(c != 'c' && c != 'l' && c != 'p') {
					System.out.println("Invalid Choice\n" +
							   "Please use a valid option (C/L/P)");
					badInput = true;
					continue;
				} //END If Choice Invalid
				badInput = false;
				switch(c) {
				case 'c': updateCipher(); break;
				case 'l': updateLength(); break;
				case 'p': updateProtocol(); break;
				} //END Switch Choice
			} //END While Bad Input
			writeConf();
		} catch(Exception e) {
			log("ERROR: " + e.toString());
			return false;
		} //END Try/Catch
		return true;
	} //END configure()

	public void updateCipher() {
		boolean badInput = true;
		while(badInput) {
			System.out.print("Please choose new cipher:\n" +
					 "1)  AES\n" +
					 "2)  AESWrap\n" +
					 "3)  ARCFOUR\n" +
					 "4)  Blowfish\n" +
					 "5)  DES\n" +
					 "6)  DESede\n" +
					 "7)  DESedeWrap\n" +
					 "8)  PBEWithMD5AndDES\n" +
					 "9)  PBEWithMD5AndTripleDES\n" +
					 "10) PBEWithSHA1AndDESede\n" +
					 "11) PBEWithSHA1AndRC2_40\n" +
					 "12) RC2\n" +
					 "13) RSA\n\n" +
					 ": ");
			String input = mConsole.readLine();
			try {
				int n = (new Integer(input)).intValue();
				switch(n) {
				case 1: sCipher = "AES"; break;
				case 2: sCipher = "AESWrap"; break;
				case 3: sCipher = "ARCFOUR"; break;
				case 4: sCipher = "Blowfish"; break;
				case 5: sCipher = "DES"; break;
				case 6: sCipher = "DESede"; break;
				case 7: sCipher = "DESedeWrap"; break;
				case 8: sCipher = "PBEWithMD5AndDES"; break;
				case 9: sCipher = "PBEWithMD5AndTripleDES"; break;
				case 10: sCipher = "PBEWithSHA1AndDESede"; break;
				case 11: sCipher = "PBEWithSHA1AndRC2_40"; break;
				case 12: sCipher = "RC2"; break;
				case 13: sCipher = "RSA"; break;
				default: throw new Exception("Invalid Selection");
				} //END Switch N
				badInput = false;
				log("New Cipher: " + sCipher);
			} catch(Exception e) {
				log("ERROR: " + e.toString());
				System.out.println("Please make a numeric choice 1-13");
				badInput = true;
			} //END Try/Catch
		} //END While Bad Input
	} //END updateCipher()

	public void updateLength() {
		log("Updating key length...");
		boolean badInput = true;
		while(badInput) {
			System.out.print("Select new key length\n" +
					 "1) 256\n" +
					 "2) 512\n" +
					 "3) 1024\n" +
					 "4) 2048\n\n" +
					 ": ");
			try {
				String input = mConsole.readLine();
				int n = (new Integer(input)).intValue();
				switch(n) {
				case 1: nKeyLen = 256; break;
				case 2: nKeyLen = 512; break;
				case 3: nKeyLen = 1024; break;
				case 4: nKeyLen = 2048; break;
				} //END Switch N
				log("New key Length: " + nKeyLen);
				badInput = false;
			} catch(Exception e) {
				System.out.println("Please make a numeric selection 1-4");
			} //END Try/Catch
		} //END While Bad Input
	} //END updateLength()

	public void updateProtocol() {
		log("Updating protocol...");
		boolean badInput = true;
		while(badInput) {
			System.out.print("Please select a key generation protocol...\n" +
					 "1) SKIP\n" +
					 "2) Generated\n\n" +
					 ": ");
			try {
				String input = mConsole.readLine();
				int n = (new Integer(input)).intValue();
				switch(n) {
				case 1: sProtocol = "SKIP"; break;
				case 2: sProtocol = "Generated"; break;
				default: throw new Exception("Invalid Selection");
				} //END Switch N
				badInput = false;
			} catch(Exception e) {
				badInput = true;
				log("ERROR: " + e.toString());
				System.out.println("Please make a numeric selection between 1 and 2");
			} //END Try/Catch
		} //END While Bad Input
		log("New Protocol: " + sProtocol);
	} //END updateProtocol()

	public void writeConf() {
		log("Saving configuration...");
		try {
			File f = new File(".wupconf");
			FileWriter fOut = new FileWriter(f);
			fOut.write("alg=" + sCipher + "\n" +
				   "len="  + nKeyLen + "\n" +
				   "pro=" + sProtocol);
			fOut.flush();
			fOut.close();
		} catch(Exception e) {
		} //END Try/Catch
	} //END writeConf()

	public boolean remove() {
		if(nV > 1) log("Starting File Removal...");
		try {
			System.out.println("TODO remove()");
		} catch(Exception e) {
			log("ERROR: " + e.toString());
			return false;
		} //END Try/Catch
		return true;
	}

	public void upload() {
		if(nV > 1) log("Starting File Upload...");
		try {
			System.out.println("=====================");
			listLocalFiles(sCWD, false);

			File f = null;
			String path = "", fName = "";
			boolean badInput = true;
			while(badInput) {
				System.out.print("Enter the name of the file you wish to upload...\n: ");
				path = mConsole.readLine();
				fName = "";
				if(path == null || path.isEmpty())
					throw new Exception("Null User Input");
				f = new File(path);
				if(!f.isFile() || !f.canRead()) {
					badInput = true;
					System.out.println("Invalid File Selected");
				} else {
					badInput = false;
					//System.out.println("sFS: " + sFS + "\npath: " + path);
					String[] tmpAry = path.split(sFS);
					fName = tmpAry[(tmpAry.length - 1)];
				} //END If/Else Full Name NULL/Empty
			} //END While Bad Input

			//Notify Server of File Name
			//FORMAT:
			//File Name...
			//[FILE]
			//[END]
			send(fName + "\n[FILE]");

			//Receive server confirmation...
			receive();
			if(!sStringBuffer.contains("[RECEIVED]"))
				throw new Exception("Server Confirmation Failed");

			//Pack file for transit...
			byte[] fBytes = new byte[(int)f.length()];
			FileInputStream fIn = new FileInputStream(f);
			fIn.read(fBytes);
			fBytes = encrypt(fBytes);
			//Send it...
			sendBytes(fBytes);

			//Receive server confirmation...
			receive();
			if(!sStringBuffer.contains("[SUCCESS]"))
				throw new Exception("File Transfer Error");
		} catch(Exception e) {
			errorOut(e);
		} //END Try/Catch
	} //END upload()

	private boolean download() {
		if(nV > 1) log("Starting File Download...");
		try {
			//Get the list of files...
			//FORMAT:
			//File1
			//...
			//FileN
			//[LIST]
			//[END]
			receive();
			int i = 0;
			String[] list = sStringBuffer.split("\n");
			System.out.println("=====================");
			while(!(sLineBuffer = list[i]).contains("[LIST]")) {
				System.out.println(sLineBuffer);
				++i;
			} //END while Line in String Buffer
			boolean badChoice = true;
			while(badChoice) {
				System.out.print("What file would you like to download?\n: ");
				sLineBuffer = mConsole.readLine();
				if(!sStringBuffer.contains(sLineBuffer + "\n")) {
					badChoice = true;
					System.out.println("Please select a valid file...");
				} else badChoice = false;
				//END If Bad Choice
			} //END While Bad Choice
			send(sLineBuffer + "\n[FILE]");
			if(nV > 1) log("Notified Server. Waiting on File Transfer...");

			//Receive it...
			byte[] fBytes = receiveBytes();
			fBytes = decrypt(fBytes);
			//Write it...
			FileOutputStream fOut = new FileOutputStream(sLineBuffer);
			fOut.write(fBytes); fOut.flush(); fOut.close();
			//Verify it...
			File test = new File(sLineBuffer);
			if(!test.isFile() || !test.canRead()) {
				send("[FAILED]");
				return false;
			} //END Test File
			send("[SUCCESS]");
		} catch(Exception e) {
			log("File Download Failed");
			errorOut(e);
		} //END Try/Catch
		return true;
	} //END download()

	private void listLocalFiles(String n, boolean recurse) {
		if(nV > 1) log("listLocalFiles(" + n + ") START");
		File dir = new File(n);
		if(dir.isFile()) {
			System.out.println(dir.getName());
			return;
		}
	
		File[] list = dir.listFiles();
		File f;
		for(int i = 0; i < list.length; i++) {
			f = list[i];
			if(f.isDirectory() && recurse) listLocalFiles(n + sFS + f.getName(), recurse);
			else System.out.println(n + sFS + f.getName());
		} //END For Name in List
	} //END listLocalFiles(String)


//-------------------
//	I/O Functions
	private String toHexString(byte[] b) {
		StringBuffer sBuff = new StringBuffer();
		int length = b.length;
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7',
				    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		for(int i = 0; i < length; i++) {
			int high = ((b[i] & 0xf0) >> 4); 
			int low = (b[i] & 0x0f);
			sBuff.append(hexChars[high]);
			sBuff.append(hexChars[low]);
		} //END For Bytes in B[] 
		return sBuff.toString();
	} //END toHexString(byte[])

	public static String md5(char[] p) {
		String md5 = null;
		return md5;
	} //END md5(char[])

	public static String md5(String str) {
		// http://viralpatel.net/blogs/java-md5-hashing-salting-password/
		String md5 = null;
		if(null == str) return null;
		try {
			MessageDigest dig = MessageDigest.getInstance("MD5");
			dig.update(str.getBytes(), 0, str.length());
			md5 = new BigInteger(1, dig.digest()).toString(16);
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		} //END Try/Catch
		return md5;
	} //END md5(String)

	public String receive() {
		if(nV > 1) log("Receiving Server Response...");
		//Clear Buffers
		sLineBuffer = sStringBuffer = "";
		try {
			//If this is a secure transmission...
			if(bEncrypt) {
				//Read Bytes & Decrypt
				sStringBuffer = new String(decrypt(receiveBytes()));
				if(sStringBuffer == null || sStringBuffer.isEmpty())
					throw new Exception("NULL Server Input");
				sStringBuffer = sStringBuffer.trim();
				if(nV > 3) log("Received:\n" + sStringBuffer + "\n"
						+ "========= END SERVER =========");
				return sStringBuffer;
			} //END If Encrypted

			//Otherwise proceed normally
			//While we don't have the end string...
			while(!sLineBuffer.equals("[END]")) {
				//...get the next line
				sLineBuffer = mInputStream.readLine();
				if(sLineBuffer == null || sLineBuffer.isEmpty())
					throw new Exception("NULL Server Input");
				//...add it to the buffer
				sStringBuffer += sLineBuffer + "\n";
			} //END While NOT END
			if(nV > 2) log("Received: " + sStringBuffer + "\n"
					+ "========= END SERVER =========");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		return sStringBuffer;
	} //END receive()

	public byte[] receiveBytes() {
		byte[] retVal = null;
		int b;
		try {
			//Get the length of incoming bytes
			int l = mDInStream.readInt();
			retVal = new byte[l];
			//If there are bytes to receive...
			if(l > 0) //...then read them
				mDInStream.readFully(retVal);
			if(nV > 2) log("Received Bytes:\n" + toHexString(retVal));
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return retVal;
	} //END receiveBytes()

	private byte[] decrypt(byte[] cipher) {
		if(cipher == null) return null;
		byte[] plain = null;
		try {
			//Decrypt & Convert Cipher Bytes to Plain Text
			plain = mDCipher.doFinal(cipher);
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return plain;
	} //END decrypt()

	public boolean send(String msg) {
		if(nV > 1) log("Sending message to server...");
		try {
			//If a secure transmission...
			if(bEncrypt) {
				//Encrypt it...
				byte[] c = encrypt(msg);
				//& send
				if(!sendBytes(c)) return false;
				if(nV > 2) log("Successfully Sent Encrypted Message: " + msg + "\n"
						+ "========= END CLIENT =========");
				return true;
			} //END If Encrypted

			//Otherwise, proceed normally
			msg += "\n[END]";
			if(nV > 2) log("Sending String:\n" + msg + "\n"
					+ "========= END CLIENT =========");
			mOutputStream.println(msg);
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		return true;
	} //END Send()

	public boolean sendBytes(byte[] b) {
		//Check Input
		if(b == null) return false;
		try {
			if(nV > 3) log("Sending " + b.length + " bytes to server:\n" + toHexString(b));
			//Notify Server of Bytes Length
			mDOutStream.writeInt(b.length);
			//Send the Bytes
			mRawOutStream.write(b);
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return true;
	} //sendBytes(byte[])

	private byte[] encrypt(String plain) {
		//Check Input
		if(plain == null) return null;
		byte[] cipher = null;
		try {
			//Convert String to Bytes & Encrypt
			cipher = mECipher.doFinal(plain.getBytes());
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return cipher;
	} //END encrypt(String)

	private byte[] encrypt(byte[] plain) {
		//Check Input...
		if(plain == null) return null;
		byte[] cipher = null;
		try {	//Encrypt Bytes...
			cipher = mECipher.doFinal(plain);
		} catch(Exception e) {
			errorOut(e);
		} //END Try/Catch
		return cipher;
	} //END encrypt(byte[])

	public static void log(String msg) {
		if(nV > 0)
			System.out.println((new Date()).toString() + " (CLIENT): " + msg);
	} //END log(String)

	public static void printUsage() {
		System.out.println("USAGE: java WEEUp [port] [host]\n"
				  + "\t[port] : Remote port to connect on\n"
				  + "\t[host] : Host name or address of server to connect to");
	} //END printUsage()

	public static void help() {
		System.out.println("Please Follow the On-Screen Prompts\n"
				+ "Or Contact admin@wiseeyesent.com if you require assistance.");
	} //END help()

	public void quit() {
		if(nV > 1) log("Sending Quit String...");
		send("[QUIT]");
		log("Good Bye!");
		System.exit(0);
	} //END quit()

	public static void errorOut(String msg, Exception e) {
	        log(msg);
	        e.printStackTrace();
	        System.exit(-1);
	} //END errorOut(String, Exception)

	public static void errorOut(Exception e) {
		errorOut(e.toString(), e);
	}
} //END WEEUp
