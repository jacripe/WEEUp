/** HEADER
 */

/****************************************************************
 * 			INCLUDES
 ****************************************************************/
import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/****************************************************************
 * 			CLASS DEFINITION
 ****************************************************************/

public class WEEUp {
//***************************************************************
//			DATA MEMBERS
	private enum State { LOGIN, MAIN, PROFILE, TRANSFER };

	private static int	nVerbosity = 1;

	private int		nPort;
	private String		sHostName;
	private String		sStringBuffer;
	private String		sLineBuffer;
	private String		sVersion = "v0.1";

	private Socket		mSocket;
	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;
	
	private Console		mConsole = System.console();

	//Whether encryption has been initialized
	private boolean			bEncrypt = false;
	//Diffie-Hellman Values
	//From Server
	private static BigInteger	nDHp;	//Modulus P
	private static BigInteger	nDHg;	//Generator G
	//From Client
	private static BigInteger	nKx;	//Private X
	private static BigInteger	nKy;	//Private Y
	private static BigInteger	nKey;	//Private Key

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
			mInputStream = new BufferedReader(
					new InputStreamReader(
					mSocket.getInputStream()));
			log("Created Input Stream");
			mOutputStream = new PrintWriter(
					mSocket.getOutputStream(), true);
			log("Created Output Stream");
			sStringBuffer = null;
			bEncrypt = false;
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
		log("Initializing Encryption");
		if(!initEncryption())
			errorOut("Encryption Initialization Failed",
				new Exception("Encryption Error"));
		log("Encryption Initialized");
		bEncrypt = true;
		log("login() DONE");
	}
	
	private boolean initEncryption() {
		log("initEncryption() START");
		try {
		} catch(Exception e) {
			errorOut(e.toString(), e);
		}
		log("initEncryption() DONE");
		return true;
	}

	//NOTE: This function was created as part of original specifications & should not be used
	private boolean manKeyValGen() {
		log("manKeyValGen() START");
		try {
			/*KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DiffieHellman");
			kpGen.initialize(1024);
			log("Initialized Key Pair Generator");
			KeyPair pair = kpGen.generateKeyPair();
			log("Generated Key Pair");
			KeyFactory kFactory = KeyFactory.getInstance("DiffieHellman");
			DHPublicKeySpec kSpec = (DHPublicKeySpec) kFactory.getKeySpec(
                        			pair.getPublic(), DHPublicKeySpec.class);
			log("Initialized Key Factory & Obtained Spec");*/
			log("Waiting on Diffie-Hellman Values...");
			receive();
			log("Received Server P String: " + sStringBuffer);
			try { nDHp = new BigInteger(sStringBuffer.split("\n")[0]); }
			catch(NumberFormatException e) { errorOut(e.toString(), e); }
			send("[RECEIVED]");
			receive();
			log("Received Server G String: " + sStringBuffer);
			try { nDHg = new BigInteger(sStringBuffer.split("\n")[0]); }
			catch(NumberFormatException e) { errorOut(e.toString(), e); }
			send("[RECEIVED]");
			
			log("Generating Private Key Values");
			nKx = new BigInteger(nKeyLen-1, nPrimeCert, mSecRan);
			log("KeyX: " + nKx.toString());
			nKy = nDHg.modPow(nKx, nDHp);
			log("KeyY: " + nKy.toString());
			log("Waiting on Server g^x mod p...");
			receive();
			log("Received Server Y Value: " + sStringBuffer);
			try { nKey = new BigInteger(sStringBuffer.split("\n")[0]); }
			catch(NumberFormatException e) { errorOut(e.toString(), e); }
			send("[RECEIVED]");
			send(nKy.toString());
			receive();
			if(!sStringBuffer.contains("[RECEIVED]")) {
				errorOut("Failed Sending Y Value to Server",
					new Exception("Encryption Initialization Error"));
			}
			nKey = nKey.modPow(nKx, nDHp);
			log("Generated Key: " + nKey.toString());
		} catch(Exception e) {
			errorOut("Enctyption Initialization Error", e);
		}
		log("manKeyValGen() DONE");
		//return true;
		return false; //Always return false because it should not be used
	}

	public static String md5(String str) {
		//log("md5() START");
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
		//log("md5() DONE");
		return md5;
	}
		

	private void mainMenu() {
		log("mainMenu() START");
		try {
			boolean badInput = true;
			while(badInput) {
				System.out.print("Enter Your Choice (M/P/T/Q/H)\n: ");
				sLineBuffer = mConsole.readLine();
				if(sLineBuffer == null) {
					log("NULL Input Received");
					System.out.println("Please make a valid selection");
				} else
					sLineBuffer = sLineBuffer.trim().toLowerCase();
				if(sLineBuffer.equals("q")) {
					quit();
				} else if(sLineBuffer.equals("h")) {
					help();
				} else if(sLineBuffer.equals("m") || sLineBuffer.equals("p")
					|| sLineBuffer.equals("t") || sLineBuffer.equals("u")) {
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
						errorOut("Unknown Selection: " + sLineBuffer,
							new Exception("Invalid Input"));
				} //END if/else
			} //END while
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END try/catch
		log("mainMenu() DONE");
	} //END mainMenu()

	private void profile() {
		log("profile() START");
		log("profile() DONE");
	} //END profile

	private void transfer() {
		log("transfer() START");
		log("transfer() DONE");
	}

	public String receive() {
		log("receive() START");
		sLineBuffer = sStringBuffer = "";
		try {
			int i = 0;
			while(!sLineBuffer.equals("[END]")) {
				//log("while loop " + i); i++;
				sLineBuffer = mInputStream.readLine();
				if(sLineBuffer == null)
					errorOut("Received NULL from Server",
						new Exception("NULL Server Input"));
				else {
					if(bEncrypt)
						sLineBuffer = decrypt(sLineBuffer);
					log("Received: " + sLineBuffer);
					sStringBuffer += sLineBuffer + "\n";
				}
			} //END while
		} catch(Exception e) {
			errorOut("Error: " + e, e);
		}
		log("receive() DONE");
		return sStringBuffer;
	}

	private String decrypt(String cipher) {
		log("decrypt() START");
		String plain = cipher;
		log("decrypt() DONE");
		return plain;
	}

	public void send(String msg) {
		log("send() START");
		try {
			msg += "\n[END]";
			if(bEncrypt)
				msg = encrypt(msg);
			log("Sending String: " + msg);
			mOutputStream.println(msg);
			log("String Sent");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}
		log("send() DONE");
	}

	private String encrypt(String plain) {
		log("encrypt() START");
		String cipher = plain;
		log("encrypt() DONE");
		return cipher;
	}

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

	public static void quit() {
		//send("[QUIT]");
		log("Good Bye!");
		System.exit(0);
	}

	public static void errorOut(String msg, Exception e) {
	        log(msg);
	        e.printStackTrace();
	        System.exit(-1);
	}
}