/** HEADER
 */

/****************************************************************
 * 			INCLUDES
 ***************************************************************/
import java.io.*;
import java.net.*;
import java.math.*;
import java.util.*;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/****************************************************************
 * 			CLASS DEFINITION
 ***************************************************************/

public class WEEUpD implements Runnable {
//***************************************************************
// 			DATA MEMBERS
	private enum State { START, CREATE, LOGIN, MAIN, PROFILE, TRANSFER };

	private int		nPort;
	private int		nIP;
	private String		sHostName;
	private String		sLineBuffer;
	private String		sStringBuffer;
	private String		sVersion = "v0.1";

	private ServerSocket	mServerSocket;
	private Socket		mClientSocket;

	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;

	private File		fPasswd = new File("passwd");

	private State		mState;

	//Whether encryption has been initialized
	private boolean			bEncrypt = false; 
	//private static final BigInteger p = new BigInteger(1024, 32, new SecureRandom());
	//private static final BigInteger g = new BigInteger("3");
	//Diffie-Hellman Values
	private static BigInteger 	nDHp;	//Modulus P
	private static BigInteger	nDHg;	//Genertor G
	private static BigInteger	nKx;	//Private X value
	private static BigInteger	nKy;	//Private Y value
	private static BigInteger	nKey;	//Private Key
	//TODO Make configurable
	private static final int	nKeyLength = 1024; //Length of Key
	private static final int	nPrimeCert = 0; //Certainty of Number Being Prime 

	private static SecureRandom	mSecRan = new SecureRandom();

//**************************************************************
// 			MAIN				
	public static void main(String[] args) {
		log("WEEUpD Started");	
		WEEUpD d = parseArgs(args);

		log("Starting Main Loop");
		while(true) {
			d.listenSocket();
		}
		//log("Finished Main Loop");
		//log("WEEUpD Done");
	}

//****************************************************************
// 			FUNCTIONS
	WEEUpD() {
		log("new WEEUpD()");
		nPort = 4321;
		sHostName = "localhost";
		this.createSocket();
	}

	WEEUpD(int p) {
		log("new WEEUpD(" + p + ")");
		nPort = p;
		sHostName = "localhost";
		this.createSocket();
	}

	public void createSocket() {
		log("createSocket() START");
		try {
			mServerSocket = new ServerSocket(nPort);
			log("Created Server Socket");
			mClientSocket = null;
			mInputStream = null;
			mOutputStream = null;
			sStringBuffer = null;
			mState = State.START; //LOGIN;
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}
		log("createSocket() DONE");
	}

	public void run() {
		log("run() START");
		try {
			mInputStream = new BufferedReader(
					new InputStreamReader(
					mClientSocket.getInputStream()));
			log("Created Input Stream");

			mOutputStream = new PrintWriter(
					mClientSocket.getOutputStream(), true);
			log("Created Output Stream");

			log("Starting Listen Loop");
			while (true) {
				if(!doShit()) {
					log("run() - doShit FAILED");
					log("Stopping run...");
					return;
				}
				/*if(!sendMenu()) {
					log("run() - sendMenu FAILED");
					log("Stopping run...");
					return;
				}
				if(!processInput()) {
					log("run() - processInput FAILED");
					log("Stopping run...");
					return;
				}*/
			}
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}

		log("run() DONE");
	}
	
	public static WEEUpD parseArgs(String[] a)  {
		log("parseArgs() START");
		System.out.println("ARGS:");
		for(String s: a)
			System.out.println("\t" + s);

		try {
			switch(a.length) {
			case 0:
				log("No arguments");
				return new WEEUpD();
			case 1:
				return new WEEUpD(Integer.parseInt(a[0]));
			default:
				log("Too many arguments. Using default constructor");
				printUsage();
				return new WEEUpD();
			}
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}

		log("Missed the switch statement. Using default constructor");
		return new WEEUpD();
	}

	public void listenSocket() {
		log("listenSocket() START");
		try {
			mClientSocket = mServerSocket.accept();
			log("Created New Client Socket");
			Thread t = new Thread(this);
			t.run();
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}

		log("listenSocket() DONE");
	}

	public boolean doShit() {
		log("doShit() START");
		boolean success = sendMenu();
		if(!success)
			return false;
		switch(mState) {
		case START:
			success = start();
			break;
		case CREATE:
			success = create();
			break;
		case LOGIN:
			success = login();
			break;
		case MAIN:
			success = main();
			break;
		case PROFILE:
			success = profile();
			break;
		case TRANSFER:
			success = transfer();
			break;
		default:
			errorOut("UNKNOWN STATE",
				new Exception("Uknown State"));
			success = false;
		}
		if(!success)
			return false;
		return true; //processInput();
	}

	// TODO This method should really not be using sStringBuffer
	public boolean sendMenu() {
		log("sendMenu() START");
		String s = "";
		switch(mState) {
		case START:
			s = "WEEUpD " + sVersion + "\n"
			+ "(K) 2014 J. A. Cripe <wiseeyesent.com>\n"
			+ "\nWhat would you like to do?\n"
			+ "C) Create an account\n"
			+ "L) Login\n"
			+ "[START]";
			break;
		case CREATE:
			s = "Please enter your user name and password (twice)\n"
			+ "[CREATE]";
			break;
		case LOGIN:
			s = "Please sign in...\n"
			+ "[LOGIN]";
			break;
		case MAIN:
			s = "\tWEEUpD " + sVersion + "\n"
			+ "M) Main Menu\n"
			+ "P) User Profile\n"
			+ "T) File Transfer\n"
			+ "U) Unknown State\n"
			+ "Q) Quit\n"
			+ "H) Help\n"
			+ "Please enter your choice (M/P/T/U/Q/H)\n"
			+ "[MAIN]";
			break;
		case PROFILE:
			s = "\tUser Profile\n"
			+ "[PROFILE]";
			break;
		case TRANSFER:
			s = "\tFile Transfer\n"
			+ "[TRANSFER]";
			break;
		default:
			s = "WARNING! Unknown State!\n"
			+ "[UNKNOWN]";
			break;
		}
		if(!send(s))
			return false;
		log("sendMenu() DONE");
		return true;
	}

	private boolean start() {
		log("start() START");
		String input = receive();
		if(input == null) {
			log("Received NULL from User");
			resetClient();
			return false;
		} //END if
		input = input.trim().toLowerCase();
		if(input.equals("c")) {
			log("Received CREATE request...");
			mState = State.CREATE;
			return true;
		} else if(input.equals("l")) {
			log("Received LOGIN request...");
			mState = State.LOGIN;
			return true;
		} else
			log("Received Invalid User Input");
		//END if/else
		log("start() DONE");
		return false;
	}

	private boolean create() {
		log("create() START");
		boolean failed = true;
		while(failed) {
			String user = receive();
			if(user == null) {
				log("Received NULL User");
				resetClient();
				return false;
			} else if (user.contains("[FAILED]")) {
				log("Client failed user name selection");
				failed = true;
				continue;
			} //END if
			user = user.trim().toLowerCase();
			if(!userAvail(user)) {
				send("Invalid Username\n[FAILED]");
				return true;
			}
			send("[RECEIVED]");
			String hash = receive();
			if(hash == null) {
				log("Received NULL Hash");
				resetClient();
				return false;
			} else if(hash.contains("[FAILED]")) {
				log("Client failed password entry");
				failed = true;
				continue;				
			} //END if
			// TODO Write User/Hash to passwd
			try {
				FileWriter passwdOut = new FileWriter("passwd", true);
				passwdOut.write(user + ":" + hash);
				passwdOut.flush();
				passwdOut.close();
			} catch(Exception e) {
				errorOut("Error writing to passwd", e);
				resetClient();
				return false;
			}
			send("[SUCCESS]");
			mState = State.START;
			failed = false;
		}
		log("create() DONE");
		return true;
	}
	
	private boolean login() {
		log("login() START");

		//TODO Change this to a configurable variable later
		int badLogins = 0;
		while(badLogins < 3 && badLogins >= 0) {
			String user = receive();
			if(user == null) {
				log("Received NULL User");
				resetClient();
				return false;
			}
			user = user.trim().toLowerCase();
			send("[RECEIVED]");
			String hash = receive();
			if(hash == null) {
				log("Received NULL Hash");
				resetClient();
				return false;
			}
			hash = hash.trim();
			if(!verifyLogin(user, hash)) {
				badLogins++;
				send("[FAILED]");
			} else {
				mState = State.MAIN;
				badLogins = -1;
			}
		}
		if(badLogins >= 3)
			resetClient();
		//else if(badLogins == -1) {
		else {
			send("[SUCCESS]");
			log("Initializing Encryption");
			if(!initEncryption()) {
				log("Error Initializing Encryption");
				return false;
			} else {
				log("Encryption Initialized");
				bEncrypt = true;
			}
		}

		log("login() DONE");
		return true;
	}

	private boolean initEncryption() {
		log("initEncryption() START");
		try {
			//Generate initial Diffie-Hellman Values
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DiffieHellman");
			kpGen.initialize(nKeyLength);
			log("Initialized Key Pair Generator with Diffie-Hellman");
			KeyPair pair = kpGen.generateKeyPair();
			log("Generated Key Pair");
			KeyFactory kFactory = KeyFactory.getInstance("DiffieHellman");
			DHPublicKeySpec kSpec = (DHPublicKeySpec) kFactory.getKeySpec(
						pair.getPublic(), DHPublicKeySpec.class);
			log("Initialized Key Factory & Obtained Public Key Spec");
			nDHp = kSpec.getP();
			nDHg = kSpec.getG();
			log("DH Values:\np = " + nDHp.toString() + "\n"
			+ "g = " + nDHg.toString());

			//Distribute DH Values to Client
			send(nDHp.toString());
			receive();
			if(!sStringBuffer.contains("[RECEIVED]")) {
				log("Failed Sending Prime Modulus P to Client");
				resetClient();
				return false;
			}
			send(nDHg.toString());
			receive();
			if(!sStringBuffer.contains("[RECEIVED]")) {
				log("Failed Sending Generator G to Client");
				resetClient();
				return false;
			}

			log("Generating Private Key Values");
			//Select Random Key X/Y Values
			nKx = new BigInteger(nKeyLength-1, nPrimeCert, mSecRan);
			log("KeyX: " + nKx.toString());
			nKy = nDHg.modPow(nKx, nDHp);
			log("KeyY: " + nKy.toString());
			log("Sending G^x mod P to Client...");
			send(nKy.toString());
			receive();
			if(!sStringBuffer.contains("[RECEIVED]")) {
				log("Failed Sending G^x mod P to Client");
				resetClient();
				return false;
			}
			log("Waiting on Client's G^x mod P Value");
			receive();
			log("Received Client's Y Value: " + sStringBuffer);
			try { nKey = new BigInteger(sStringBuffer.split("\n")[0]); }
			catch(NumberFormatException e) {
				log("Invalid G^x mod P Value From Client!");
				resetClient();
				return false;
			}
			send("[RECEIVED]");
			nKey = nKey.modPow(nKx, nDHp);
			log("Generated Key: " + nKey.toString());
		} catch(Exception e) {
			log("Error during encryption initialization...");
			resetClient();
			return false;
		}
		log("initEncryption() DONE");
		return true;
	}

	private boolean main() {
		log("main() START");
		String input = receive();
		if(input == null)
			return false;
		input = input.trim().toLowerCase();
		System.out.println("(CLIENT): " + input);
		log("main() DONE");
		return true;
	}

	private boolean profile() {
		log("profile() START");
		log("profile() DONE");
		return true;
	}

	private boolean transfer() {
		log("transfer() START");
		log("transfer() DONE");
		return true;
	}

	private boolean userAvail(String usr) {
		log("userAvail() START");
		log("Checking if username is already taken");
		log("User: " + usr);

		try {
			BufferedReader passwdInput = new BufferedReader(new FileReader("passwd"));
			String line = passwdInput.readLine();
			while(line != null) {
				String[] auth = line.split(":");
				if(usr.equals(auth[0])) {
					log("Found Username in passwd: " + usr);
					return false;
				} else
					line = passwdInput.readLine();
			} //END while
		} catch(Exception e) {
			errorOut(e.toString(), e);
			resetClient();
			return false;
		}
		log("userAvail() DONE");
		return true;
	}

	private boolean verifyLogin(String user, String hash) {
		log("verifyLogin() START");
                log("Authenticating login information...");
                if(user == null || hash == null) {
                        log("Received NULL input");
                        return false;
                }

                log("User: " + user + " | Hash: " + hash);
                try {
                        BufferedReader passwdInput = new BufferedReader(new FileReader("passwd"));
                        String line = passwdInput.readLine();
                        while(line != null) {
                                String[] auth = line.split(":");
                                if(user.equals(auth[0]) && hash.equals(auth[1])) {
					log("Login Successful");
                                        return true;
				} else
                                        line = passwdInput.readLine();
                        }
			log("Login Failed");
                        return false;
                } catch(IOException e) {
                        System.out.println("I/O Error During checkLogin()");
                        System.out.println(e);
                        System.exit(-1);
                }
		log("verifyLogin() DONE");
                return false;
	}

	/*public boolean processInput() {
		log("processInput() START");
		receive();
		try {
			sStringBuffer = null;
			sStringBuffer = mInputStream.readLine();
			if(sStringBuffer == null) {
				log("Received NULL From Client");
				resetClient();
				return false;
			}
	
			log("Received String: " + sStringBuffer);
			log("processInput() DONE");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}

		log("processInput() DONE");
		return true;
	}*/

	private boolean send(String s) {
		log("send() START");
		s += "\n[END]";
		if(bEncrypt)
			s = encrypt(s);
		log("Sending String to Client:\n" + s + "|Fin.");
		try { mOutputStream.println(s); }
		catch(Exception e) {
			log("Error while sending output to client");
			e.printStackTrace();
			resetClient();
			return false;
		}
		log("send() DONE");
		return true;
	}

	private String encrypt(String plain) {
		log("encrypt() START");
		String cipher = plain;
		log("encrypt() DONE");
		return cipher;
	}

	public String receive() {
		log("receive() START");
		String retVal = "";
		sLineBuffer = sStringBuffer = "";
		try {
			while(!sLineBuffer.equals("[END]")) {
				sLineBuffer = mInputStream.readLine();
				if(sLineBuffer == null) {
					log("Received NULL from Client");
					resetClient();
					return null;
				} else {
					if(bEncrypt)
						sLineBuffer = decrypt(sLineBuffer);
					log("Received: " + sLineBuffer);
					if(sLineBuffer.equals("[QUIT]")) {
						log("Received Quit String");
						resetClient();
					} else if(!sLineBuffer.equals("[END]"))
						sStringBuffer += sLineBuffer + "\n";
				}
			}
		} catch(Exception e) {
			log("Error while receiving input from client");
			e.printStackTrace();
			resetClient();
			return null;
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

	public void resetClient() {
		log("resetClient() START");
		try {
			mOutputStream.close();
			log("Closed Output Stream");

			mInputStream.close();
			log("Closed Input Stream");

			mClientSocket.close();
			log("Closed Client Socket");

			mState = State.START; //LOGIN;
			bEncrypt = false;
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}
		log("resetClient() DONE");
	}

	public static void printUsage() {
		String msg = "USAGE: java WEEUpD [port] [host]\n";
		System.out.println(msg);
	}

	public static void log(String s) {
		System.out.println((new Date()).toString() + " (SERVER): " + s);
	}

	public static void errorOut(String msg, Exception e) {
		log(msg);
		e.printStackTrace();
		System.exit(-1);
	}
}
