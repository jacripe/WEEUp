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
		//w.listenSocket();
		log("Starting Input Loop");
		while(true) {
			w.doShit();
			//w.send();
			//break;
		}
		//log("WEEUp Client Finished");
	}


//**************************************************************
//			FUNCTIONS

	WEEUp() {
		log("new WEEUp()");
		nPort = 4321;
		sHostName = "localhost";
		this.createSocket();
	}

	WEEUp(int p) {
		log("new WEEUp(" + p + ")");
		nPort = p;
		sHostName = "localhost";
		this.createSocket();
	}

	WEEUp(int p, String h) {
		log("new WEEUp(" + p + ", " + h + ")");
		nPort = p;
		sHostName = h;
		this.createSocket();
	}
	
	public void createSocket() {
		log("createSocket() START");
		try {
			mSocket = new Socket(sHostName, nPort);
			log("Created Socket");
			mRawInStream = mSocket.getInputStream();
			mDInStream = new DataInputStream(mRawInStream);
			mInputStream = new BufferedReader(
					new InputStreamReader(
					mRawInStream));
			log("Created Input Stream");
			mRawOutStream = mSocket.getOutputStream();
			mDOutStream = new DataOutputStream(mRawOutStream);
			mOutputStream = new PrintWriter(mRawOutStream, true);

			log("Created Output Stream");
			sStringBuffer = null;
			bEncrypt = false;
			log("Initializing Encryption");
			if(!initEncryption())
				throw new Exception("Encryption Initialization Failed");
			log("Encryption Initialized");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}

		log("createSocket() DONE");
	}

	public void doShit() {
		log("doShit() START");
		receive();
		String[] strArray = sStringBuffer.split("\n");
		for(int i = 0; i < strArray.length; i++) {
			String s = strArray[i];
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
			else if(s != null)
				System.out.println(s);
			//END if/else
		} //END for
		log("doShit() DONE");
	} //END doShit()

	private void start() {
		log("start() START");
		boolean failed = true;
		while(failed) {
			System.out.print("Please enter your choice (C/L)\n: ");
			sLineBuffer = mConsole.readLine();
			if(sLineBuffer == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			sLineBuffer = sLineBuffer.trim().toLowerCase();
			log("Received User Input: " + sLineBuffer);
			if(!sLineBuffer.equals("c") && !sLineBuffer.equals("l")) {
				System.out.println("Invalid Input!\nPlease try \"C\" or \"L\"...\n");
				failed = true;
			} else {
				send(sLineBuffer);
				failed = false;
			} //END if/else
		} //END while
		
		log("start() DONE");
	}

	private void create() {
		log("create() START");
		boolean failed = true;
		while(failed) {
			System.out.print("Enter New Username: ");
			String user = mConsole.readLine();
			if(sLineBuffer == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			user = user.trim().toLowerCase();
			log("Received User: " + user);
			send(user);
			receive();
			log("Received Server Response: " + sStringBuffer);
			if(!sStringBuffer.contains("[RECEIVED]")) {
				System.out.println("Bad Username. Plese try again...");
				continue;
			}
			System.out.print("Enter New Password: ");
			String pass = new String(mConsole.readPassword());
			if(pass == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			String hash = md5(pass + ":" + user);
			log("Received Hash: " + hash);
			/*send(hash);
			receive();
			log("Received Server Response: " + sStringBuffer);
			if(!sStringBuffer.contains("[RECEIVED]"))
				errorOut("Unknown Server Response",
					new Exception("Unknown Server Response"));*/
			System.out.print("Re-enter Password: ");
			pass = new String(mConsole.readPassword());
			if(pass == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			String hash2 = md5(pass + ":" + user);
			log("Received Hash: " + hash2);
			if(!hash.equals(hash2)) {
				System.out.println("Invalid Input!\nPasswords do not match.");
				send("[FAILED]");
				failed = true;
				continue;
			}
			send(hash2);
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
			} //END if/else
		} //END while
		log("create() DONE");
	}

	private void login() {
		log("login() START");
		boolean validUser = false;
		boolean validPass = false;
		int failedLogins = 0;
		log("Starting Login Loop");
		while(failedLogins < 3 && failedLogins >= 0) {
			System.out.print("Enter User Name\n: ");
			String user = mConsole.readLine();
			if(user == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			log("Received User: " + user);
			send(user);
			receive();
			log("Received Server Response: " + sStringBuffer);
			System.out.print("Enter Password\n: ");
			String hash = new String(mConsole.readPassword());
			if(sLineBuffer == null)
				errorOut("Received NULL Input",
					new Exception("Null User Input"));
			hash = md5(hash + ":" + user);
			log("Received Hash: " + hash);
			send(hash);
			receive();
			log("Received Server Response: " + sStringBuffer);
			if(sStringBuffer.contains("[SUCCESS]")) {
				log("Successful Login!");
				failedLogins = -1;
			} else
				failedLogins++;
			if(failedLogins >= 3)
				errorOut("Failed Login Attempt",
					new Exception("Invalid Credentials"));
		}
		log("login() DONE");
	}
	
	//Adapted from Oracle documentation:
	//http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
	private boolean initEncryption() {
		log("initEncryption() START");
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
		}
		log("initEncryption() DONE");
		return true;
	} //END initEncryption

	private String toHexString(byte[] b) {
		log("toHexString() START");
		StringBuffer sBuff = new StringBuffer();
		int length = b.length;
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7',
				    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		for(int i = 0; i < length; i++) {
			int high = ((b[i] & 0xf0) >> 4); 
			int low = (b[i] & 0x0f);
			sBuff.append(hexChars[high]);
			sBuff.append(hexChars[low]);
		} //END for 
		log("toHexString() DONE");
		return sBuff.toString();
	} //END toHexString

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
		}
		return md5;
	}
		

	private void mainMenu() {
		log("mainMenu() START");
		try {
			char choice = 'z';
			boolean badInput = true;
			while(badInput) {
				System.out.print("Enter Your Choice (M/P/T/Q/H)\n: ");
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null) {
					log("NULL Input Received");
					System.out.println("Please make a valid selection");
					continue;
				} else {
					sLineBuffer = sLineBuffer.trim().toLowerCase();
					choice = sLineBuffer.charAt(0);	
				} //END If/Else Input NULL

				if(choice == 'q')
					quit();
				else if(choice == 'h')
					help();
				else if(choice == 'm' || choice == 'p' || choice == 't' || choice == 'u') {
					badInput = false;
					if(sLineBuffer.equals("m"))
						send("[MAIN]");
					else if(sLineBuffer.equals("p"))
						send("[PROFILE]");
					else if(sLineBuffer.equals("t"))
						send("[TRANSFER]");
					else if(sLineBuffer.equals("u"))
						send("[UNKNOWN]");
					else
						throw new Exception("Unknown Selection: " + sLineBuffer);
				} else {
					System.out.println("Sorry, invalid input.\n"
					+ "Please try: (M)ain Menu, (P)rofile, (T)ransfer, (U)nknown, "
					+ "(H)elp or (Q)uit");
				}//END If/Else Choice
			} //END While (Bad Input)
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		log("mainMenu() DONE");
	} //END mainMenu()

	private void profile() {
		log("profile() START");
		try {
			char choice = 'z';
			boolean badInput = true;
			while(badInput) {
				System.out.print("Enter Your Choice (M/H/Q)\n: ");
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null) {
					log("NULL Input Received");
					System.out.println("Please make a valid selection");
					continue;
				} else {
					sLineBuffer = sLineBuffer.trim().toLowerCase();
					choice = sLineBuffer.charAt(0);
				} //END If/Else Input Null

				if(choice == 'q')
					quit();
				else if(choice == 'h')
					help();
				else if(choice == 'm') {
					badInput = false;
					send("[MAIN]");
				} else
					System.out.println("Sorry, invalid selection.\n"
					+ "Please try: (M)ain Menu, (H)elp or (Q)uit");
				//END If/Else Choice
			} //END While (Bad Input)
		} catch(Exception e) {
			errorOut("ERROR: " + e.toString(), e);
		} //END Try/Catch
		log("profile() DONE");
	} //END profile

	private void transfer() {
		log("transfer() START");
		try {
			char choice = 'z';
			boolean badInput = true;
			while(badInput) {
				System.out.print("Enter Your Choice (M/H/Q)\n: ");
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null) {
					log("NULL User Input");
					System.out.println("Please make a valid selection");
					continue;
				} else {
					sLineBuffer = sLineBuffer.trim().toLowerCase();
					choice = sLineBuffer.charAt(0);
				} //END If/Else Input NULL

				if(choice == 'q')
					quit();
				else if(choice == 'h')
					help();
				else if(choice == 'm') {
					badInput = false;
					send("[MAIN]");
				} else
					System.out.println("Sorry, invalid selection.\n"
					+ "Please try: (M)ain Menu, (H)elp or (Q)uit");
				//END If/Else Choice
			} //END While (Bad Input)
		} catch(Exception e) {
			errorOut("ERROR: " + e.toString(), e);
		}
		log("transfer() DONE");
	}

	public String receive() {
		log("receive() START");
		sLineBuffer = sStringBuffer = "";
		try {
			//If this is a secure transmission...
			if(bEncrypt) {
				//Read Bytes & Decrypt
				sStringBuffer = decrypt(receiveBytes());
				if(sStringBuffer == null)
					throw new Exception("NULL Server Input");
				sStringBuffer = sStringBuffer.trim();
				//log("Received:\n" + sStringBuffer);
				return sStringBuffer;
			} //END if

			//Otherwise proceed normally
			while(!sLineBuffer.equals("[END]")) {
				sLineBuffer = mInputStream.readLine();
				if(sLineBuffer == null)
					throw new Exception("NULL Server Input");
				//log("Received: " + sLineBuffer.trim());
				sStringBuffer += sLineBuffer + "\n";
			} //END While
			log("Received: " + sStringBuffer);
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		log("receive() DONE");
		return sStringBuffer;
	} //END Receive

	public byte[] receiveBytes() {
		log("receiveBytes() START");
		byte[] retVal = null;
		int b;
		try {
			int l = mDInStream.readInt();
			retVal = new byte[l];
			if(l > 0)
				mDInStream.readFully(retVal);
			log("Received Bytes:\n" + toHexString(retVal));
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END try/catch
		log("receiveBytes() DONE");
		return retVal;
	}

	private String decrypt(byte[] cipher) {
		if(cipher == null) return null;
		String plain = null;
		try {
			//Decrypt & Convert to String
			plain = new String(mDCipher.doFinal(cipher));
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END Try/Catch
		return plain;
	} //END Decrypt()

	public boolean send(String msg) {
		log("send() START");
		try {
			//If a secure transmission...
			if(bEncrypt) {
				//Encrypt it...
				byte[] c = encrypt(msg);
				//& send
				if(!sendBytes(c)) return false;
				log("Successfully Sent Encrypted Message: " + msg);
				return true;
			} //END if

			//Otherwise, proceed normally
			msg += "\n[END]";
			log("Sending String: " + msg);
			mOutputStream.println(msg);
			log("String Sent");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		log("send() DONE");
		return true;
	} //END Send()

	public boolean sendBytes(byte[] b) {
		if(b == null) return false;
		log("sendBytes() START");
		try {
			log("Sending " + b.length + " bytes to server:\n" + toHexString(b));
			mDOutStream.writeInt(b.length);
			mRawOutStream.write(b);
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END try/catch
		log("sendBytes() DONE");
		return true;
	}

	private byte[] encrypt(String plain) {
		if(plain == null) return null;
		byte[] cipher = null;
		try {
			//Convert String to Bytes & Encrypt
			cipher = mECipher.doFinal(plain.getBytes());
		} catch(Exception e) {
			errorOut(e.toString(), e);
		} //END try/catch
		return cipher;
	} //END encrypt()

	public static WEEUp parseArgs(String[] a) {
		log("parseArgs() START");
		WEEUp retVal = null;

		System.out.println("ARGS:");
		for(String s: a) {
			System.out.println("\t" + s);
		}

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
		}
		if(retVal == null)
			retVal = new WEEUp();

		log("parseArgs() DONE");
		return retVal;
	}

	public static void log(String msg) {
		if(nVerbosity > 0)
			System.out.println((new Date()).toString() + " (CLIENT): " + msg);
	}

	public static void printUsage() {
		System.out.println("USAGE: java WEEUp [port] [hostname]");
	}

	public static void help() {
		System.out.println("Please Follow the On-Screen Prompts\n"
				+ "Or Contact admin@wiseeyesent.com if you require assistance.");
	}

	public void quit() {
		send("[QUIT]");
		log("Good Bye!");
		System.exit(0);
	}

	public static void errorOut(String msg, Exception e) {
	        log(msg);
	        e.printStackTrace();
	        System.exit(-1);
	}
}
