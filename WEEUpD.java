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

public class WEEUpD { //implements Runnable {
//***************************************************************
// 			DATA MEMBERS
//	private enum State { START, CREATE, LOGIN, MAIN, PROFILE, TRANSFER, UNKNOWN };

	private int		nPort;
	private int		nIP;
	private String		sHostName;
/*	private String		sLineBuffer;
	private String		sStringBuffer;
	private String		sVersion = "v0.4a";
*/
	private ServerSocket	mServerSocket;
	private Socket		mClientSocket;

/*	private OutputStream	mRawOutStream = null;
	private InputStream	mRawInStream = null;

	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;

	private DataInputStream		mDInStream;
	private DataOutputStream	mDOutStream;

	private File			fPasswd = new File("passwd");

	private State			mState;

	private static int		nCount = 0;
	private static long		nSize = 0;
	private static String		sUser = "";
	private static String		sDocRoot = "";
	private static final String	sCWD = System.getProperty("user.dir");
	private static final String	sFS = System.getProperty("file.separator");

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
*/
//**************************************************************
// 			MAIN				
	public static void main(String[] args) {
		log("WEEUpD Started");	
		WEEUpD d = parseArgs(args);

		log("Starting Main Loop");
		while(true) {
			d.listenSocket();
		} //END Main Loop
	} //END main(ARGS)

//****************************************************************
// 			FUNCTIONS
//-----------------
//	CONSTUCTORS

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

//----------------
//	Initilizer
	public static WEEUpD parseArgs(String[] a)  {
		String msg = "Parsing Arguments:";
		for(String s: a) msg += "\t" + s;
		log(msg);

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
			} //END Switch A Length
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		log("Missed the switch statement. Using default constructor");
		return new WEEUpD();
	} //END parseArgs(String[])

	public void createSocket() {
		try {
			mServerSocket = new ServerSocket(nPort);
			log("Created Server Socket");
			mClientSocket = null;
/*			mInputStream = null;
			mOutputStream = null;
			sStringBuffer = null;
			log("Initialized Streams to NULL");
			mState = State.START;
			log("Initialized State to START");*/
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		}
	}

//----------------
//	Thread Run
	public void listenSocket() {
		log("Waiting on client connection...");
		try {
			mClientSocket = mServerSocket.accept();
			log("Created New Client Socket");
			Thread t = new Thread(new ServerSlave(mClientSocket, mServerSocket, "SessionID"));
			t.start();
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
	} //END listenSocket()
	
	public static void printUsage() {
		String msg = "USAGE: java WEEUpD [port] [host]\n"
			   + "\t[port] : Local Port to Listen On\n"
			   + "\t[host] : Host name to use (NOT IMPLEMENTED)";
		System.out.println(msg);
	} //END printUsage()

	public static void log(String s) {
		//TODO unique server hostname/process identifier
		System.out.println((new Date()).toString() + " (Server): " + s);
	} //end log(String)

	public static void errorOut(String msg, Exception e) {
		log(msg);
		e.printStackTrace();
		System.exit(-1);
	} //END errorOut(String, Exception)
} //END WEEUpD

class ServerSlave implements Runnable {
	private enum State { START, CREATE, LOGIN, MAIN, PROFILE, TRANSFER, UNKNOWN };

	private String		sLineBuffer;
	private String		sStringBuffer;
	private String		sVersion = "v0.4a";
	private String		sID = "";

	private ServerSocket	mServerSocket;
	private Socket		mClientSocket;

	private OutputStream	mRawOutStream = null;
	private InputStream	mRawInStream = null;

	private BufferedReader	mInputStream;
	private PrintWriter	mOutputStream;

	private DataInputStream		mDInStream;
	private DataOutputStream	mDOutStream;

	private File			fPasswd = new File("passwd");

	private State			mState;

	private static int		nCount = 0;
	private static long		nSize = 0;
	private static String		sUser = "";
	private static String		sDocRoot = "";
	private static final String	sCWD = System.getProperty("user.dir");
	private static final String	sFS = System.getProperty("file.separator");

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

	public ServerSlave(Socket client, ServerSocket server, String id) {
		mClientSocket = client;
		mServerSocket = server;
		mState = State.START;
		sID = id;
		log("New Server Slave: " + sID);
	}

	public void run() {
		log("Starting Run...");
		try {
			mRawInStream = mClientSocket.getInputStream();
			mDInStream = new DataInputStream(mRawInStream);
			mInputStream = new BufferedReader(
					new InputStreamReader(mRawInStream));
			log("Created Input Streams");

			mRawOutStream = mClientSocket.getOutputStream();
			mDOutStream = new DataOutputStream(mRawOutStream);
			mOutputStream = new PrintWriter(
					mRawOutStream, true);
			log("Created Output Streams");

			log("Initializing Encryption");
			if(!initEncryption()) {
				log("Error Initializing Encryption");
				throw new Exception("Encryption Initialization Failed");
			} else
				log("Encryption Initialized");
			//END If/Else Initialize Encryption FAILED

			log("Starting Listen Loop");
			while (true) {
				if(!doShit()) {
					log("run() - doShit FAILED");
					log("Stopping run...");
					resetClient();
					return;
				} //END If doShit FAILED
			} //END While True
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
	} //END run()

	//Adapted from Oracle documentation
	//http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
	//TODO Make Configurable (SKIP/Generated Parms, Cipher, Key Length, Etc.)
	private boolean initEncryption() {
		log("Initializing Encryption");
		try {
			/* TODO GENERATE PARAMETERS
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
		} //END Try/Catch
		return true;
	} //END initEncryption()

//--------------------
//	Menu Functions
	public boolean doShit() {
		log("Time to do something...");
		//Send Menu to Client
		boolean success = sendMenu();
		//If there was a problem...
		if(!success)
			//...start over
			return false;
		//END If NOT Success
		//Otherwise, run the appropriate function
		switch(mState) {
		case START:
			success = start();
			break;
		case CREATE:
			success = create();
			break;
		case LOGIN:
			success = login();
			if(success) success = checkUserProfile();
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
		} //END Switch STATE
		//If there was a problem...
		if(!success)
			//...we should start over
			return false;
		//Otherwise, we're good
		return true;
	} //END doShit()

	public boolean sendMenu() {
		log("Sending menu to client...");
		String s = "";
		switch(mState) {
		case START:
			log("Start Menu");
			s = "WEEUpD " + sVersion + "\n"
			+ "(K) 2014 J. A. Cripe <wiseeyesent.com>\n"
			+ "\nWhat would you like to do?\n"
			+ "C) Create an account\n"
			+ "L) Login\n"
			+ "[START]";
			break;
		case CREATE:
			log("Create Menu");
			s = "Please enter your user name and password (twice)\n"
			+ "[CREATE]";
			break;
		case LOGIN:
			log("Login Menu");
			s = "Please sign in...\n"
			+ "[LOGIN]";
			break;
		case MAIN:
			log("Main Menu");
			s = "WEEUpD " + sVersion + "\n"
			+ "-----------------\n"
			+ "M) Main Menu\n"
			+ "P) User Profile\n"
			+ "T) File Transfer\n"
			+ "Q) Quit\n"
			+ "H) Help\n"
			+ "Please enter your choice (M/P/T/Q/H)\n"
			+ "[MAIN]";
			break;
		case PROFILE:
			log("Profile Menu");
			s = "User Profile\n"
			+ "-----------------\n"
			+ "User: " + sUser + "\n"
			+ "Doc Root: " + sDocRoot + "\n"
			+ "Cipher: " + sCipher + "\n"
			+ "Count: " + nCount + "\n"
			+ " Size: " + nSize + "\n"
			+ "-----------------\n"
			+ "\n"
			+ "(R)eset Password\n"
			+ "(T)ransfer Files\n"
			+ "(M)ain Menu\n"
			+ "(H)elp\n"
			+ "(Q)uit\n"
			+ "[PROFILE]";
			break;
		case TRANSFER:
			log("Transfer Menu");
			s = "\tFile Transfer\n"
			+ "-----------------\n"
			+ "DIR: " + sDocRoot + "\n"
			+ "Count: " + nCount + "\n"
			+ "Size: " + nSize + "\n"
			+ "-----------------\n"
			+ "\n"
			+ "(L)ist Files\n"
			+ "(U)pload File\n"
			+ "(M)ain Menu\n"
			+ "(P)rofile\n" 
			+ "(H)elp\n"
			+ "(Q)uit\n"
			+ "[TRANSFER]";
			break;
		default:
			log("Unknown State");
			s = "WARNING! Unknown State!\n"
			+ "[UNKNOWN]";
			break;
		} //END Switch STATE
		if(!send(s))
			return false;
		//END If Send FAILED
		return true;
	} //END sendMenu()

//-----------------------
//	Command Functions
	private boolean start() {
		log("Do they want to create a user or login?");
		//Get User Input
		String input = receive();
		//If we received NULL input...
		if(input == null) {
			//...start over
			log("Received NULL from User");
			resetClient();
			return false;
		} //END If Input NULL
		//Otherwise, process the input...
		if(input.equals("[CREATE]")) {
			log("Received CREATE request...");
			mState = State.CREATE;
			return true;
		} else if(input.equals("[LOGIN]")) {
			log("Received LOGIN request...");
			mState = State.LOGIN;
			return true;
		} else
			log("Received Invalid User Input");
		//END If/Else Input
		return false;
	} //END start()

	private boolean create() {
		log("Creating a new user...");
		boolean failed = true;
		//While we haven't succeeded...
		while(failed) {
			//...get user name
			String user = receive();
			//...check for null
			if(user == null) {
				log("Received NULL User");
				resetClient();
				return false;
			} else if (user.contains("[FAILED]")) {
				log("Client failed user name selection");
				failed = true;
				continue;
			} //END If/Else User NULL/FAILED
			user = user.trim().toLowerCase();
			if(!userAvail(user)) {
				send("Invalid Username\n[FAILED]");
				return true;
			} //END If User NOT Avail
			//...notify client
			send("[RECEIVED]");
			//...get password hash
			String hash = receive();
			//...check for null/failed
			if(hash == null) {
				log("Received NULL Hash");
				resetClient();
				return false;
			} else if(hash.contains("[FAILED]")) {
				log("Client failed password entry");
				failed = true;
				continue;
			} //END If/Else Hash NULL/FALIED
			//...write user:hash to passwd file
			try {
				log("Writing " + user + ":" + hash + " to passwd...");
				FileWriter passwdOut = new FileWriter("passwd", true);
				passwdOut.write(user + ":" + hash + "\n");
				passwdOut.flush();
				passwdOut.close();
				log("DONE");
			} catch(Exception e) {
				errorOut("Error writing to passwd", e);
				resetClient();
				return false;
			} //END Try/Catch
			//...notify client
			send("[SUCCESS]");
			mState = State.LOGIN;
			failed = false;
		} //END While Failed
		return true;
	} //END create()
	
	private boolean login() {
		log("Starting Login...");
		//TODO Change this to a configurable variable later
		int badLogins = 0;
		//While we still have attempts & haven't succeeded
		while(badLogins < 3 && badLogins >= 0) {
			//...get user name
			String user = receive();
			if(user == null) {
				log("Received NULL User");
				resetClient();
				return false;
			} //END If User NULL
			user = user.trim().toLowerCase();
			sUser = user;
			sDocRoot = sCWD + sFS + "users" + sFS + sUser;
			//...notify client
			send("[RECEIVED]");
			//...get password hash
			String hash = receive();
			if(hash == null) {
				log("Received NULL Hash");
				resetClient();
				return false;
			} //END If Hash NULL
			hash = hash.trim();
			//..check for valid credentials
			if(!verifyLogin(user, hash)) {
				badLogins++;
				send("[FAILED]");
			} else {
				mState = State.MAIN;
				badLogins = -1;
			} //END If/Else Failed Verify Login
		} //END While Bad Logins
		//If we used up our attempts, start over
		if(badLogins >= 3)
			resetClient();
		//Otherwise, we're good
		else if(badLogins == -1)
			send("[SUCCESS]");
		//END If/Else Bad Logins >3/-1
		return true;
	} //END login()

	private boolean mainMenu() {
		log("Starting Main Menu...");
		//Get User Input & Check for NULL
		String input = receive();
		if(input == null)
			return false;
		input = input.trim();
		System.out.println("(CLIENT): " + input);
		if(input.equals("[MAIN]")) {
			; //Do Nothing, You're Already There
		} else if(input.equals("[PROFILE]")) {
			mState = State.PROFILE;
		} else if(input.equals("[TRANSFER]")) {
			mState = State.TRANSFER;
		} else {
			//mState = State.UNKNOWN;
			log("Unknown Input Received: " + input);
		} //END If/Else Input
		return true;
	} //END mainMenu()

	private boolean profile() {
		log("Starting User Profile...");
		//Get User Input & Check For NULL
		String input = receive();
		if(input == null)
			return false;
		input = input.trim();
		System.out.println("(CLIENT): " + input);
		//Process It...
		if(input.contains("[MAIN]"))
			mState = State.MAIN;
		else if(input.contains("[PROFILE]"))
			; //Do Nothing. You're there already
		else if(input.contains("[TRANSFER]"))
			mState = State.TRANSFER;
		else if(input.contains("[RESET]"))
			resetPassword();
		else
			mState = State.UNKNOWN;
		//END If/Else Input
		return true;
	} //END profile()

	private boolean transfer() {
		log("Starting File Transfer...");
		//Get User Input & Check For NULL
		String input = receive();
		if(input == null)
			return false;
		input = input.trim();
		System.out.println("(CLIENT): " + input);
		//Process It...
		if(input.contains("[MAIN]"))
			mState = State.MAIN;
		else if(input.contains("[PROFILE]"))
			mState = State.PROFILE;
		else if(input.contains("[LIST]"))
			listFiles();
		else if(input.contains("[UPLOAD]"))
			upload();
		else if(input.contains("[TRANSFER]"))
			; //Do Nothing. You're there already
		else
			mState = State.UNKNOWN;
		//END If/Else Input
		return checkUserProfile();
		//return true;
	} //END transfer()

//---------------------------
//	Operational Functions
	private boolean userAvail(String usr) {
		log("Checking if username is already taken");
		log("User: " + usr);

		try {
			//Open Passwd File Reader
			BufferedReader passwdInput = new BufferedReader(new FileReader("passwd"));
			//Get the first line
			String line = passwdInput.readLine();
			//As long as we have a line...
			while(line != null) {
				//...parse it
				String[] auth = line.split(":");
				//...if we found the requested user name
				if(usr.equals(auth[0])) {
					//...they'll have to try again
					log("User name is TAKEN");
					return false;
				} else
					//...otherwise, read the next line
					line = passwdInput.readLine();
				//END If/Else User Found
			} //END While Line NOT NULL
		} catch(Exception e) {
			errorOut(e.toString(), e);
			resetClient();
			return false;
		} //END Try/Catch
		log("User name is FREE");
		return true;
	} //END userAvail(String)

	private boolean verifyLogin(String user, String hash) {
		log("Authenticating login information...");
		if(user == null || hash == null) {
			log("Received NULL input");
			return false;
		} //END If User NULL OR Hash NULL

		log("User: " + user);
		log("Hash: " + hash);
		try {
			//Open Passwd File Reader...
			BufferedReader passwdInput = new BufferedReader(new FileReader("passwd"));
			//Get First Line...
			String line = passwdInput.readLine();
			//While we still have a line...
			while(line != null) {
				//...parse the credentials
				//FORMAT:
				//user:hash
				String[] auth = line.split(":");
				//...if credentials are valid...
				if(user.equals(auth[0]) && hash.equals(auth[1])) {
					//...they've logged in
					log("Login Successful");
					return true;
				} else //...otherwise...
					//...check the next line
					line = passwdInput.readLine();
				//END If/Else User & Hash Authorized
			} //END While Line NOT NULL
			//If we're here, we ran out of users
			log("Login Failed");
			return false;
		} catch(IOException e) {
			System.out.println("I/O Error During checkLogin()");
			System.out.println(e);
			System.exit(-1);
		} //END Try/Catch
		return false; //Assume failure
	} //END verifyLogin(String, String)

	private boolean checkUserProfile() {
		log("Checking User Profile...");
		try {
			File usrDir = new File(sDocRoot);
			if(usrDir.isDirectory())
				log("User Dir: " + usrDir);
			else
				if(usrDir.mkdir())
					log("Created User Directory: " + usrDir);
				else
					throw new Exception("Unable to create user directory....");
				//END If/Else Make Directory
			//END If/Else Is Directory
			File[] files = usrDir.listFiles();
			nCount = files.length;
			nSize = 0;
			for(int i = 0; i < files.length; i++)
				nSize += files[i].length();
		} catch(Exception e) {
			log("ERROR: " + e.toString());
			return false;
		} //END Try/Catch
		return true;
	} //END checkUserProfile()

	private boolean resetPassword() {
		log("Resetting Password...");
		boolean failed = true;
		//While we haven't succeeded...
		while(failed) {
			//...get password hash
			String hash = receive();
			//...check for null/failed
			if(hash == null) {
			        log("Received NULL Hash");
			        resetClient();
			        return false;
			} else if(hash.contains("[FAILED]")) {
			        log("Client failed password entry");
			        failed = true;
			        continue;
			} //END If/Else Hash NULL/FALIED
			//...update passwd file contents with new hash
			try {
				//...get the current contents
				log("Reading current passwd file...");
				BufferedReader fIn = new BufferedReader(new FileReader("passwd"));
				String line = null; String user = null;
				String fTxt = "";
				while((line = fIn.readLine()) != null) {
					fTxt += line + "\n";
					//...if this line matches the current user, save it
					if(line.startsWith(sUser + ":")) user = line;
				} //END While Read Line
				fIn.close(); //...input stream no longer needed

				//...if we didn't find current user
				if(user == null || user.isEmpty()) //something is wrong
					throw new Exception("User Passwd Not Found");
				log("Found User Hash: " + user);

				//...update to the new hash
				log("Updating " + sUser + " hash...");
				String curHash = user.split(":")[1];
				log("Current Hash: " + curHash);
				log("New Hash: " + hash);
				user = user.replaceAll(curHash, hash);
				log("New User String: " + user);
				fTxt = fTxt.replaceAll(sUser + ":" + curHash, user);
				log("New Passwd Contents:\n" + fTxt);

				//...put it back in passwd file
				log("Writing new contents to passwd...");
				FileWriter passwdOut = new FileWriter("passwd", false);
				passwdOut.write(fTxt);
				passwdOut.flush();
				passwdOut.close();
				log("DONE");
			} catch(Exception e) {
				errorOut("Error writing to passwd", e);
				resetClient();
				return false;
			} //END Try/Catch
			//...notify client
			send("[SUCCESS]");
			failed = false;
		} //END While Failed
		return true;
	} //END resetPassword()

	private boolean listFiles() {
		log("Listing Files...");
		try {
			//Formulate File List Response
			//FORMAT:
			//Doc Root: ...
			//File List:
			//File 1
			//...
			//File n
			//[LIST]
			//[END]
			String files = "Doc Root: " + sDocRoot + "\n"
				     + "File List:\n";
			File dir = new File(sDocRoot);
			File[] list = dir.listFiles();
			for(int i = 0; i < list.length; i++)
				files += list[i].getName() + " : "
					+ list[i].length() + "\n";
			files += "[LIST]";
			send(files);
		} catch(Exception e) {
			log("ERROR: " + e.toString());
			return false;
		} //END Try/Catch
		return true;
	} //END listFiles()

	private boolean upload() {
		log("Uploading File...");
		try {
			//Receive File Notification:
			//FORMAT:
			//File Name...
			//[FILE]
			//[END]
			receive();
			if(!sStringBuffer.contains("[FILE]"))
				throw new Exception("Invalid File Notification From Client");
			String fName = sDocRoot + sFS + sStringBuffer.split("\n")[0];
			log("Received File Name: " + fName);

			//TODO Check for duplicate files

			//Notify client...
			send("[RECEIVED]");

			//Receive the file
			byte[] fBytes = receiveBytes();
			fBytes = decrypt(fBytes);
			FileOutputStream fOut = new FileOutputStream(fName);
			fOut.write(fBytes);
			File test = new File(fName);
			if(test.isFile() && test.canRead())
				send("[SUCCESS]");
			else {
				send("[FAILED]");
				return false;
			}
		} catch(Exception e) {
			log("ERROR: " + e.toString());
			return false;
		}
		return true;
	}

	private boolean send(String s) {
		log("Sending message to client...");
		try {
			//If this is a secure transmission...
			if(bEncrypt) {
				//Encrypt it...
				byte[] b = encrypt(s);
				//And send the bytes...
				if(sendBytes(b) == false) return false;
				log("Successfully Sent Encrypted Message:\n" + s);
				System.out.println("========= END SERVER =========\n");
				return true;
			} //END If Encrypted
			//Otherwise, proceed normally
			s += "\n[END]";
			log("Sending String to Client:\n" + s + "|Fin.");
			mOutputStream.println(s);
		} catch(Exception e) {
			log("Error while sending string to client");
			e.printStackTrace();
			resetClient();
			return false;
		} //END Try/Catch
		log("Successfully Sent Message");
		return true;
	} //END send(String)

	private boolean sendBytes(byte[] b) {
		//Check Input
		if(b == null) return false;
		try {
			log("Sending " + b.length + " bytes to client:\n" + toHexString(b));
			//Notify client of incoming byte length
			mDOutStream.writeInt(b.length);
			//Send the bytes
			mRawOutStream.write(b);
		} catch(Exception e) {
			log("Error Sending Bytes to Client");
			e.printStackTrace();
			resetClient();
			return false;
		} //END Try/Catch
		return true;
	} //END sendBytes(byte[])

	private byte[] encrypt(String plain) {
		//Check Input
		if(plain == null) return null;
		byte[] cipher;
		try {
			//Convert Plain Text to Cipher Bytes
			cipher = mECipher.doFinal(plain.getBytes());
		} catch(Exception e) {
			log("Error Performing Encryption: " + e.toString());
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		return cipher;
	} //END encrypt(String)

	private byte[] encrypt(byte[] plain) {
		//Check Input...
		if(plain == null) return null;
		byte[] cipher = null;
		try {	//Encrypt Plain Bytes
			cipher = mECipher.doFinal(plain);
		} catch(Exception e) {
			log("Error Encrypting Data: " + e.toString());
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		return cipher;
	} //END encrypt(byte[])

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

	public String receive() {
		//Clear buffers
		sLineBuffer = sStringBuffer = "";
		try {
			//If a secure transmission
			if(bEncrypt) {
				sStringBuffer = new String(decrypt(receiveBytes()));
				if(sStringBuffer == null)
					throw new Exception("Null Client Input");
				else if(sStringBuffer.isEmpty())
					throw new Exception("Empty Client Input");
				else
					log("Received:\n" + sStringBuffer);
			} else //Otherwise, proceed normally...
			//NOTE: Indentation Intentionally Removed
			//As long as haven't gotten the end notification...
			while(!sLineBuffer.equals("[END]")) {
				//...keep pulling data
				sLineBuffer = mInputStream.readLine();
				//If we received null input from socket...
				if(sLineBuffer == null)
					//...something went wrong
					throw new Exception("NULL Client Input");
				else if(sLineBuffer.isEmpty())
					throw new Exception("Empty Client Input");
				else {
					//...otherwise we're good
					log("Received: " + sLineBuffer);
					if(!sLineBuffer.equals("[END]"))
						sStringBuffer += sLineBuffer + "\n";
					//END If END
				} //END If/Else NULL
			} //END While NOT END
			//END If/Else Encrypted
			System.out.println("========= END CLIENT =========\n");

			//If we received the quit string
			if(sStringBuffer.contains("[QUIT]")) {
				//It would be a good idea to quit
				log("Received Quit String");
				resetClient();
				return null;
			} //END If QUIT
		} catch(Exception e) {
			log("Error while receiving input from client");
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		return sStringBuffer;
	} //END receive()

	public byte[] receiveBytes() {
		byte[] retVal = null;
		int b;
		try {
			//Get Byte Length
			int l = mDInStream.readInt();
			//Initialize Byte Array
			retVal = new byte[l];
			//Get the Bytes
			log("Reading " + l + " bytes from socket");
			if(l > 0) mDInStream.readFully(retVal);
			log("Received Bytes:\n" + toHexString(retVal));
		} catch(Exception e) {
			log("Error Receiving Bytes From Client: " + e.toString());
			return null;
		} //END Try/Catch
		return retVal;
	} //END receiveBytes()

	private byte[] decrypt(byte[] cipher) {
		if(cipher == null) return null;
		byte[] plain = null;
		try {
			plain = mDCipher.doFinal(cipher);
		} catch(Exception e) {
			log("Error During Decryption: " + e.toString());
			e.printStackTrace();
			resetClient();
			return null;
		} //END Try/Catch
		return plain;
	} //END decrypt(byte[])

	public boolean resetClient() {
		log("Resetting Client Connection");
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
			sUser = sDocRoot = "";
			mState = State.START;
			bEncrypt = false;
			log("Reset Buffers & State");
		} catch(Exception e) {
			errorOut("ERROR: " + e, e);
		} //END Try/Catch
		return false;
	} //END resetClient()

	public void log(String s) {
		//TODO unique server hostname/process identifier
		System.out.println((new Date()).toString() + " (SRV:" + sID + "): " + s);
	} //end log(String)

	public void errorOut(String msg, Exception e) {
		log(msg);
		e.printStackTrace();
		System.exit(-1);
	} //END errorOut(String, Exception)


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
