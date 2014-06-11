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

	private static int	nVerbosity = 1;

	private int		nPort;
	private String		sHostName;
	private String		sStringBuffer;
	private String		sLineBuffer;
	private String		sVersion = "v0.4a";

	private Socket		mSocket;
	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;

	private InputStream	mRawInStream;
	private OutputStream	mRawOutStream;

	private DataInputStream		mDInStream;
	private DataOutputStream	mDOutStream;
	
	private Console		mConsole = System.console();

	//Whether encryption has been initialized
	private static boolean		bEncrypt = false;//Whether or not encryption is ready
	private static String		sCipher = "DES";//Shared Cipher Algorithm

	private static DHPrivateKey	mDHPrivKey;	//Private Client DH Key Object
	private static DHPublicKey	mServerPubKey;	//Public Server DH Key
	private static byte[]		aKeyBytes;	//Shared Secret Key Byte Array
	private static SecretKey	mKey;		//Shared Secret Key Object
	private static Cipher		mECipher;	//Cipher Object for Ecnryption
	private static Cipher		mDCipher;	//Cipher Object for Decryption

	//TODO Make Configurable
	private static final int	nKeyLen = 1024;	//Key Length
	private static final int	nPrimeCert = 0;	//Certaining of Prime Number

	private static SecureRandom	mSecRan = new SecureRandom();

//**************************************************************
//			MAIN

	public static void main(String[] args) {
		log("WEEUp Client Started");
		WEEUp w = parseArgs(args);
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
		log("new WEEUp()");
		nPort = 4321;
		sHostName = "localhost";
		this.createSocket();
	} //END WEEUp()

	WEEUp(int p) {
		log("new WEEUp(" + p + ")");
		nPort = p;
		sHostName = "localhost";
		this.createSocket();
	} //END WEEUp(int)

	WEEUp(int p, String h) {
		log("new WEEUp(" + p + ", " + h + ")");
		nPort = p;
		sHostName = h;
		this.createSocket();
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
			log("No arguments. Using default constructor");
			break;
		case 1:
			retVal = new WEEUp(Integer.parseInt(a[0]));
			break;
		case 2:
			retVal = new WEEUp(Integer.parseInt(a[0]), a[1]);
			break;
		case 3:
			retVal = new WEEUp(Integer.parseInt(a[0]), a[1]);
			retVal.nVerbosity = Integer.parseInt(a[2]);
		default:
			log("Too many arguments");
			printUsage();
			log("Using default constructor");
			break;
		} //END Switch Number of Arguments
		if(retVal == null)
			retVal = new WEEUp();
		//END If No Constructor Called
		return retVal;
	} //END parseArgs(String[])

	public void createSocket() {
		log("Connecting to server...");
		try {
			mSocket = new Socket(sHostName, nPort);
			log("Created Socket");

			mRawInStream = mSocket.getInputStream();
			mDInStream = new DataInputStream(mRawInStream);
			mInputStream = new BufferedReader(
					new InputStreamReader(
					mRawInStream));
			log("Created Input Streams");

			mRawOutStream = mSocket.getOutputStream();
			mDOutStream = new DataOutputStream(mRawOutStream);
			mOutputStream = new PrintWriter(mRawOutStream, true);
			log("Created Output Stream");

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

//------------------
//	Misc Members
	public void doShit() {
		log("Time to do something...");
		//Get Server Input...
		receive();
		//Parse Input...
		String[] strArray = sStringBuffer.split("\n");
		//For Each Line...
		for(int i = 0; i < strArray.length; i++) {
			//...instantiate a variable
			String s = strArray[i];
			//...check if it's a command
			if(s.equals("[RECEIVED]"))
				log("Server Received Last Message");
			else if(s.equals("[SUCCESS]"))
				log("Transaction Successful");
			else if(s.equals("[FAILED]"))
				log("Failed Transaction");
			else if(s.equals("[START]"))
				start();
			else if(s.equals("[CREATE]"))
				create();
			else if(s.equals("[LOGIN]"))
				login();
			else if(s.equals("[MAIN]"))
				mainMenu();
			else if(s.equals("[PROFILE]"))
				profile();
			else if(s.equals("[TRANSFER]"))
				transfer();
			else if(s.equals("[UNKNOWN]"))
				errorOut("ERROR: Server in Unknown State",
					new Exception("Unknown Server State"));
			//...otherwise...
			else if(s != null)
				//...display the line to user
				System.out.println(s);
			//END If/Else Line
		} //END For Each Line
	} //END doShit()

	private void start() {
		log("Start Menu...");
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
			log("Received User Input: " + sLineBuffer);
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
		log("Creating a new user...");
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
			log("Received User: " + user);
			//...notify server
			send(user);
			receive();
			//...get the password hash twice
			log("Received Server Response: " + sStringBuffer);
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
			log("Received Hash: " + hash);
			System.out.print("Re-enter Password: ");
			pass = new String(mConsole.readPassword());
			if(pass == null || pass.isEmpty())
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			String hash2 = md5(pass + ":" + user);
			log("Received Hash: " + hash2);
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
			log("Received Server Response: " + sStringBuffer);
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
		log("Beginning login...");
		//While we have attempts remaining & haven't succeeded...
		int failedLogins = 0;
		while(failedLogins < 3 && failedLogins >= 0) {
			//...get the user name
			System.out.print("Enter User Name\n: ");
			String user = mConsole.readLine();
			if(user == null || user.isEmpty())
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			log("Received User: " + user);
			//...notify server
			send(user);
			receive();
			log("Received Server Response: " + sStringBuffer);
			if(!sStringBuffer.contains("[RECEIVED]")) {
				Exception e = new Exception("Error sending login user to server");
				errorOut(e.toString(), e);
			}  //END NOT RECEIVED

			//...get the password hash
			System.out.print("Enter Password\n: ");
			String hash = new String(mConsole.readPassword());
			//TODO String hash = md5(mConsole.readPassword());
			if(hash == null || hash.isEmpty()) {
				System.out.println("Please enter a valid username & password");
				continue;
			} //END If Hash NULL
			hash = md5(hash + ":" + user);
			log("Received Hash: " + hash);
			//...notify server
			send(hash);
			receive();
			log("Received Server Response: " + sStringBuffer);
			if(sStringBuffer.contains("[SUCCESS]")) {
				log("Successful Login!");
				failedLogins = -1;
			} else
				failedLogins++;
			//END If/Else SUCCESS
			if(failedLogins >= 3)
				errorOut("Failed Login Attempt",
					new Exception("Invalid Credentials"));
			//END If Out of Login Attempts
		} //END While Failed & Attempts Remaining
	}
	
	//Adapted from Oracle documentation:
	//http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
	private boolean initEncryption() {
		log("Initializing Encryption...");
		try {
			log("Waiting on Key Data From Server...");
			byte[] serverPubKeyBytes = receiveBytes();

			//Instantiate DH Public Key From Bytes
			KeyFactory kFac = KeyFactory.getInstance("DiffieHellman");
			log("Initialized Key Factory");
			X509EncodedKeySpec encKSpec =
				new X509EncodedKeySpec(serverPubKeyBytes);
			DHPublicKey mServerKey = (DHPublicKey) kFac.generatePublic(encKSpec);
			log("Instantiated Server Public Key");

			//Initialize Key Specifications
			DHParameterSpec kParmSpec = mServerKey.getParams();

			//Generate Client Keys
			KeyPairGenerator kPGen = KeyPairGenerator.getInstance("DiffieHellman");
			kPGen.initialize(kParmSpec);
			KeyPair keyPair = kPGen.generateKeyPair();
			log("Generated Client DH Public/Private Key Pair");

			//Initialize Key Agreement
			KeyAgreement kAgree = KeyAgreement.getInstance("DiffieHellman");
			kAgree.init(keyPair.getPrivate());
			log("Initialized Client Key Agreement");

			//Encode Public Key For Transport
			byte[] pubKeyBytes = keyPair.getPublic().getEncoded();
			log("Encoded Public Key:\n" + toHexString(pubKeyBytes));

			//Send Notification to Server
			send("[RECEIVED]");
			//Send Client Public Key to Server
			sendBytes(pubKeyBytes);
			log("Sent Encoded Public Key to Server");

			//Get Confirmation & Secret Key Length From Server
			//FORMAT:
			//[PRIVKEY]
			//Secret Key Length
			//[RECEIVED]
			//[END]
			log("Waiting on Server Response");
			receive();
			if(!sStringBuffer.contains("[RECEIVED]"))
				throw new Exception("Error Sending Public Key to Server");
			log("Received Server Response:\n" + sStringBuffer);

			//Agree Those Keys
			kAgree.doPhase(mServerKey, true);
			log("Client Key Agreement Complete");

			//Generate Symmetric Client Secret Key (Should Match Server)
			if(!sStringBuffer.contains("[PRIVKEY]"))
				throw new Exception("Error Receiving Secret Key Length From Server");
			int length = new Integer(sStringBuffer.split("\n")[1]).intValue();
			aKeyBytes = new byte[length];
			length = kAgree.generateSecret(aKeyBytes, 0);
			log("Generated Client Secret Key Bytes:\n" + toHexString(aKeyBytes));

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
			log("Generated Client Secret Key & Cipher Objects Using "
			   + sCipher + " Algorithm");

			//Get Server Confirmation to Verify En/Decryption is functional
			log("Waiting on Server Encryption Verification Test...");
			receive();
			if(!sStringBuffer.contains("[VERIFY_ENCRYPTION]"))
				throw new Exception("Bad Server Encryption Test");
			send("[SUCCESS]");

			log("Waiting on Server Confirmation...");
			receive();
			if(!sStringBuffer.contains("[SUCCESS]"))
				throw new Exception("Encryption Verification Failed");
			log("SUCCESS! ENCRYPTION IS LIVE!");
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return true;
	} //END initEncryption()

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

	private void mainMenu() {
		log("Main Menu...");
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
					log("NULL Input Received");
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
						log("Unknown Selection: (" + choice + ") "
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
		log("User Profile...");
		try {
			//Initialize Buffer
			char choice = 'z';
			//While we don't have a valid selection...
			boolean badInput = true;
			while(badInput) {
				//...prompt user
				System.out.print("Enter Your Choice (R/T/M/H/Q)\n: ");
				//...get input
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null || sLineBuffer.isEmpty()) {
					log("NULL Input Received");
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
				else if(choice == 'm' || choice == 'r' || choice == 't') {
					badInput = false;
					switch(choice) {
					case 'q': quit(); break;
					case 'h': help(); break;
					case 'm': send("[MAIN]"); break;
					case 'r': send("[RESET]"); break;
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
		log("File Transfer...");
		try {
			//Initiliaze Buffer
			char choice = 'z';
			//While we do not have a valid selection...
			boolean badInput = true;
			while(badInput) {
				//...prompt user
				System.out.print("Enter Your Choice (L/U/M/H/Q)\n: ");
				//...get input
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null || sLineBuffer.isEmpty()) {
					log("NULL User Input");
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
				else if(choice == 'm' || choice == 'l' || choice == 'u') {
					badInput = false;
					switch(choice) {
					case 'm':
						send("[MAIN]");
						break;
					case 'l':
						send("[LIST]");
						break;
					case 'u':
						send("[UPLOAD]");
						break;
					} //END Switch Choice
				} else 
					System.out.println("Sorry, invalid selection.\n"
					+ "Please try: (M)ain Menu, (H)elp or (Q)uit");
				//END If/Else Choice
			} //END While Bad Input
		} catch(Exception e) {
			errorOut("ERROR: " + e.toString(), e);
		} //END Try/Catch
	} //END transfer()

//-------------------
//	I/O Functions
	public String receive() {
		log("Receiving Server Response...");
		//Clear Buffers
		sLineBuffer = sStringBuffer = "";
		try {
			//If this is a secure transmission...
			if(bEncrypt) {
				//Read Bytes & Decrypt
				sStringBuffer = decrypt(receiveBytes());
				if(sStringBuffer == null || sStringBuffer.isEmpty())
					throw new Exception("NULL Server Input");
				sStringBuffer = sStringBuffer.trim();
				log("Received:\n" + sStringBuffer);
				System.out.println("========= END SERVER =========\n");
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
			log("Received: " + sStringBuffer);
			System.out.println("========= END SERVER =========\n");
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
			log("Received Bytes:\n" + toHexString(retVal));
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return retVal;
	} //END receiveBytes()

	private String decrypt(byte[] cipher) {
		if(cipher == null) return null;
		String plain = null;
		try {
			//Decrypt & Convert Cipher Bytes to Plain Text
			plain = new String(mDCipher.doFinal(cipher));
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return plain;
	} //END decrypt()

	public boolean send(String msg) {
		log("Sending message to server...");
		try {
			//If a secure transmission...
			if(bEncrypt) {
				//Encrypt it...
				byte[] c = encrypt(msg);
				//& send
				if(!sendBytes(c)) return false;
				log("Successfully Sent Encrypted Message: " + msg);
				System.out.println("========= END CLIENT =========\n");
				return true;
			} //END If Encrypted

			//Otherwise, proceed normally
			msg += "\n[END]";
			log("Sending String:\n" + msg);
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
			log("Sending " + b.length + " bytes to server:\n" + toHexString(b));
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

	public static void log(String msg) {
		if(nVerbosity > 0)
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
		log("Sending Quit String...");
		send("[QUIT]");
		log("Good Bye!");
		System.exit(0);
	} //END quit()

	public static void errorOut(String msg, Exception e) {
	        log(msg);
	        e.printStackTrace();
	        System.exit(-1);
	} //END errorOut(String, Exception)
} //END WEEUp
