/** HEADER
 */

/* ***************************************************************
 * 			INCLUDES
 * **************************************************************/
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
 * **************************************************************/

public class WEEUpD implements Runnable {
//***************************************************************
// 			DATA MEMBERS
	private enum State { START, CREATE, LOGIN, MAIN, PROFILE, TRANSFER, UNKNOWN };

	private int		nPort;
	private int		nIP;
	private String		sHostName;
	private String		sLineBuffer;
	private String		sStringBuffer;
	private String		sVersion = "v0.4a";

	private ServerSocket	mServerSocket;
	private Socket		mClientSocket;

	private OutputStream	mRawOutStream = null;
	private InputStream	mRawInStream = null;

	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;

	private DataInputStream		mDInStream;
	private DataOutputStream	mDOutStream;

	private File		fPasswd = new File("passwd");

	private State		mState;

	//Encryption Members
	private static boolean		bEncrypt = false; //Whether or not Encryption is Available
	private static String		sCipher;	//Cipher Algorithm to Use for Encryption
	private static Cipher		mECipher;	//Cipher Object for Encryption
	private static Cipher		mDCipher;	//Cipher Object for Decryption

	private static DHPrivateKey	mDHKey;		//DH Private Key Object
	private static DHPublicKey	mClientKey;	//Client Public Key Object
	private static byte[]		aKeyBytes;	//Shared Secret Key Byte Array
	private static SecretKey	mKey;		//Shared Secret Key Object

	//TODO Make configurable
	private static final int	nKeyLen = 1024; //Length of Key
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
		try {
			File f = new File("passwd");
			if(!f.exists())
				new FileOutputStream(f).close();
		} catch(Exception e) {
			log("ERROR! PASSWD DOES NOT EXIST & CANNOT BE CREATED!");
			e.printStackTrace();
			System.exit(-1);
		}
	}

	WEEUpD(int p) {
		log("new WEEUpD(" + p + ")");
		nPort = p;
		sHostName = "localhost";
		this.createSocket();
		try {
			File f = new File("passwd");
			if(!f.exists())
				new FileOutputStream(f).close();
		} catch(Exception e) {
			log("ERROR! PASSWD DOES NOT EXIST & CANNOT BE CREATED!");
			e.printStackTrace();
			System.exit(-1);
		}
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
			mState = State.START;
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}
		log("createSocket() DONE");
	}

	public void run() {
		log("run() START");
		try {
			mRawInStream = mClientSocket.getInputStream();
			mDInStream = new DataInputStream(mRawInStream);
			mInputStream = new BufferedReader(
					new InputStreamReader(mRawInStream));
			log("Created Input Stream");

			mRawOutStream = mClientSocket.getOutputStream();
			mDOutStream = new DataOutputStream(mRawOutStream);
			mOutputStream = new PrintWriter(
					mRawOutStream, true);
			log("Created Output Stream");

			log("Initializing Encryption");
			if(!initEncryption()) {
				log("Error Initializing Encryption");
				throw new Exception("Encryption Initialization Failed");
			} else
				log("Encryption Initialized");

			log("Starting Listen Loop");
			while (true) {
				if(!doShit()) {
					log("run() - doShit FAILED");
					log("Stopping run...");
					resetClient();
					return;
				}
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
			success = mainMenu();
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
		else if(badLogins == -1)
			send("[SUCCESS]");

		log("login() DONE");
		return true;
	}

	//Adapted from Oracle documentation
	//http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
	//TODO Make Configurable (Cipher, Key Length, Etc.)
	private boolean initEncryption() {
		log("initEncryption() START");
		try {
			/* GENERATE PARAMETERS
 			AlgorithmParameterGenerator aPGen =
				AlgorithmParameterGenerator.getInstance("DiffieHellman");
			aPGen.init(1024);
			AlgorithmParameters algParms = aPGen.generateParameters();
			DHParameterSpec dhParmSpec = (DHParameterSpec)
							algParms.getParamterSpec(DHParameterSpec.class);
			*/
			// USE SKIP DH PARAMETERS
			log("Using SKIP Diffie-Hellman Parameters");
			DHParameterSpec dhParmSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);

			//Create Server Key Pair
			KeyPairGenerator kPGen = KeyPairGenerator.getInstance("DiffieHellman");
			kPGen.initialize(dhParmSpec);
			KeyPair keyPair = kPGen.generateKeyPair();
			log("Generated Server Key Pair");

			//Create & Initialize Server Key Agreement
			KeyAgreement kAgree = KeyAgreement.getInstance("DiffieHellman");
			kAgree.init(keyPair.getPrivate());
			log("Initialized Server Key Agreement");

			//Encode Server Public Key for Transport
			byte[] pubKeyEnc = keyPair.getPublic().getEncoded();
			log("Encoded Server Public Key:\n" + toHexString(pubKeyEnc));

			//Send Encoded Public Key to Client
			sendBytes(pubKeyEnc);
			log("Sent Public Key to Client");

			//Get Client Confirmation
			log("Waiting on Client Response");
			receive();
			if(!sStringBuffer.contains("[RECEIVED]"))
				throw new Exception("Error Sending Public Key Bytes to Client");
			log("Received Client Response:\n" + sStringBuffer);

			//Receive & Parse Client Public Key
			byte[] clientPubKeyBytes = receiveBytes();
			log("Received Encoded Client Public Key:\n" + toHexString(clientPubKeyBytes));

			//Instantiate Client Public Key
			KeyFactory kFac = KeyFactory.getInstance("DiffieHellman");
			X509EncodedKeySpec encKeySpec = new X509EncodedKeySpec(clientPubKeyBytes);
			mClientKey = (DHPublicKey) kFac.generatePublic(encKeySpec);
			log("Instantiated Client Public Key");

			//Agree Those Keys
			kAgree.doPhase(mClientKey, true);
			log("Server Key Agreement Complete");

			//Generate Shared SecretKey
			aKeyBytes = kAgree.generateSecret();
			log("Generated Server Secret Key:\n" + toHexString(aKeyBytes));
			
			//Notify Client
			//FORMAT:
			//[PRIVKEY]
			//Secret Key Length
			//[RECEIVED]
			//[END]
			send("[PRIVKEY]\n" + aKeyBytes.length + "\n[RECEIVED]");
			log("Sent Secret Key Length to Client");
			log("Waiting on Client Confirmation...");

			//Get Client Confirmation & Cipher Choice
			//FORMAT:
			//[CIPHER]
			//Cipher Algorithm
			//[SUCCESS]
			//[END]
			receive();
			if(!sStringBuffer.contains("[SUCCESS]")
			|| !sStringBuffer.contains("[CIPHER]"))
				throw new Exception("Key Agreement Error");
			sCipher = sStringBuffer.split("\n")[1];
			log("Received Client Cipher Selection: " + sCipher);

			//Prep the KeyAgreement Object for Secret Key Generation
			kAgree.doPhase(mClientKey, true);

			//Generate Secret Key & Cipher Object
			mKey = kAgree.generateSecret(sCipher);
			mECipher = Cipher.getInstance(sCipher);
			mECipher.init(Cipher.ENCRYPT_MODE, mKey);
			mDCipher = Cipher.getInstance(sCipher);
			mDCipher.init(Cipher.DECRYPT_MODE, mKey);
			bEncrypt = true;
			log("Generated Server Secret Key & Cipher Objects Using "
			   + sCipher + " Algorithm");

			//Test En/Decryption
			log("Sending client encryption verification string...");
			send("[VERIFY_ENCRYPTION]");

			log("Waiting on client response...");
			receive();
			if(!sStringBuffer.contains("[SUCCESS]"))
				throw new Exception("Bad Client Encryption Verification Response");
			send("[SUCCESS]");
			log("SUCCESS! ENCRYPTION IS LIVE");
		} catch(Exception e) {
			log("Error During Encryption Initialization!");
			e.printStackTrace();
			resetClient();
			return false;
		}
		log("initEncryption() DONE");
		return true;
	}

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
		}
		return sBuff.toString();
	}

	private boolean mainMenu() {
		log("mainMenu() START");
		String input = receive();
		if(input == null)
			return false;
		input = input.trim();
		System.out.println("(CLIENT): " + input);
		if(input.equals("[MAIN]")) {
			//Do Nothing, You're Already There
		} else if(input.equals("[PROFILE]")) {
			mState = State.PROFILE;
		} else if(input.equals("[TRANSFER]")) {
			mState = State.TRANSFER;
		} else {
			mState = State.UNKNOWN;
		}
		log("mainMenu() DONE");
		return true;
	}

	private boolean profile() {
		log("profile() START");
		String input = receive();
		if(input == null)
			return false;
		input = input.trim();
		System.out.println("(CLIENT): " + input);
		if(input.equals("[MAIN]"))
			mState = State.MAIN;
		else if(input.equals("[PROFILE]"))
			; //Do Nothing. You're there already
		else if(input.equals("[TRANSFER]"))
			mState = State.TRANSFER;
		else
			mState = State.UNKNOWN;
		log("profile() DONE");
		return true;
	}

	private boolean transfer() {
		log("transfer() START");
		String input = receive();
		if(input == null)
			return false;
		input = input.trim();
		System.out.println("(CLIENT): " + input);
		if(input.equals("[MAIN]"))
			mState = State.MAIN;
		else if(input.equals("[PROFILE]"))
			mState = State.PROFILE;
		else if(input.equals("[TRANSFER]"))
			; //Do Nothing. You're there already
		else
			mState = State.UNKNOWN;
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
		try {
			//If this is a secure transmission...
			if(bEncrypt) {
				//Encrypt it...
				byte[] b = encrypt(s);
				//And send the bytes...
				if(sendBytes(b) == false) return false;
				log("Successfully Sent Encrypted Message: " + s);
				return true;
			}
			//Otherwise, proceed normally
			s += "\n[END]";
			log("Sending String to Client:\n" + s + "|Fin.");
			mOutputStream.println(s);
		} catch(Exception e) {
			log("Error while sending string to client");
			e.printStackTrace();
			resetClient();
			return false;
		}
		log("send() DONE");
		return true;
	}

	private boolean sendBytes(byte[] b) {
		if(b == null) return false;
		log("sendBytes() START");
		try {
			log("Sending " + b.length + " bytes to client:\n" + toHexString(b));
			mDOutStream.writeInt(b.length);
			mRawOutStream.write(b);
		} catch(Exception e) {
			log("Error Sending Bytes to Client");
			e.printStackTrace();
			resetClient();
			return false;
		} //END Try/Catch
		log("sendBytes() DONE");
		return true;
	} //END sendBytes()

	private byte[] encrypt(String plain) {
		if(plain == null)
			return null;
		byte[] cipher;
		try {
			cipher = mECipher.doFinal(plain.getBytes());
		} catch(Exception e) {
			log("Error Performing Encryption:\n\t" + e.toString());
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		return cipher;
	} //END encrypt()

	public String receive() {
		log("receive() START");
		//Clear buffers
		sLineBuffer = sStringBuffer = "";
		try {
			//If a secure transmission
			if(bEncrypt) {
				sStringBuffer = decrypt(receiveBytes());
				if(sStringBuffer == null)
					throw new Exception("Null Client Input");
				else
					log("Received: " + sStringBuffer);
			}
			//Otherwise ..
			else
			//As long as haven't gotten the end notification...
			while(!sLineBuffer.equals("[END]")) {
				//...keep pulling data
				sLineBuffer = mInputStream.readLine();
				//If we received null input from socket...
				if(sLineBuffer == null) {
					//...something went wrong
					log("Received NULL from Client");
					resetClient();
					return null;
				} else {
					//...otherwise we're good
					log("Received: " + sLineBuffer);
					//If it's the quit string, we should kill connection
					if(sLineBuffer.equals("[QUIT]")) {
						log("Received Quit String");
						resetClient();
						return null;
					} else if(!sLineBuffer.equals("[END]"))
						sStringBuffer += sLineBuffer + "\n";
					//END If/Else QUIT
				} //END If/Else NULL
			} //END While ![END]
			//END If/Else (Encrypted)

			//If we received the quit string
			if(sStringBuffer.contains("[QUIT]")) {
				//It would be a good idea to quit
				log("Received Quit String");
				resetClient();
				return null;
			} //END If [QUIT]
		} catch(Exception e) {
			log("Error while receiving input from client");
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		log("receive() DONE");
		return sStringBuffer;
	} //END receive()

	public byte[] receiveBytes() {
		log("receiveBytes() START");
		byte[] retVal = null;
		int b;
		try {
			int l = mDInStream.readInt();
			retVal = new byte[l];
			log("Initialized retVal[" + l + "]");
			log("Reading " + l + " bytes from socket");
			if(l > 0)
				mDInStream.readFully(retVal);
			//if((b = mRawInStream.available()) > 0)
			//	throw new Exception("Too Many Bytes, " + b + " remaining");
			log("Received Bytes:\n" + toHexString(retVal));
		} catch(Exception e) {
			/*log("Error Receiving Bytes From Client");
			e.printStackTrace();
			resetClient();*/
			return null;
		} //END Try/Catch
		log("receiveBytes() DONE");
		return retVal;
	} //END receiveBytes()

	private String decrypt(byte[] cipher) {
		if(cipher == null)
			return null;
		String plain = null;
		try {
			//Decrypt & Convert to String
			plain = new String(mDCipher.doFinal(cipher));
		} catch(Exception e) {
			log("Error During Decryption: " + e.toString());
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		return plain;
	} //END decrypt()

	public boolean resetClient() {
		log("resetClient() START");
		//Close all streams & reset to initial state
		try {
			mOutputStream.close();
			mDOutStream.close();
			mRawOutStream.close();
			log("Closed Output Stream");

			mInputStream.close();
			mDInStream.close();
			mRawInStream.close();
			log("Closed Input Stream");

			mClientSocket.close();
			log("Closed Client Socket");

			sLineBuffer = sStringBuffer = null;
			mState = State.START;
			bEncrypt = false;
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		log("resetClient() DONE");
		return false;
	} //END resetClient()

	public static void printUsage() {
		String msg = "USAGE: java WEEUpD [port] [host]\n";
		System.out.println(msg);
	} //END printUsage()

	public static void log(String s) {
		System.out.println((new Date()).toString() + " (SERVER): " + s);
	} //END log()

	public static void errorOut(String msg, Exception e) {
		log(msg);
		e.printStackTrace();
		System.exit(-1);
	} //END errorOut


//**************************************************************
// 			SKIP PROTOCOL
// SEE: http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
	private static final byte skip1024ModulusBytes[] = {
	        (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
	        (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
	        (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
	        (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
	        (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
	        (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
	        (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
	        (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
	        (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
	        (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
	        (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
	        (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
	        (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
	        (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
	        (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
	        (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
	        (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
	        (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
	        (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
	        (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
	        (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
	        (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
	        (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
	        (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
	        (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
	        (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
	        (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
	        (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
	        (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
	        (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
	        (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
	        (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
	}; //END SKIP Protocol

	private static final BigInteger	skip1024Modulus = new BigInteger(1, skip1024ModulusBytes);
	private static final BigInteger	skip1024Base = BigInteger.valueOf(2);
} //END WEEUpD
