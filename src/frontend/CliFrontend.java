package frontend;

import java.io.*;
import java.nio.file.*;

import sha.*;
/**
 * command line interface of the hash generator
 * command line arguments:
 * 		- (file path or string) (optional reference hash)
 * opens the appropriate stream to the file (or stream) and passes it to the hasher object
 * outputs the hash to the input files directory
 * 
 * @author Benjamin Roberts
 * @version 0.1.1
 */
public class CliFrontend {

	private static Path targetFilePath;
	private static Long targetFileLength;
	private static DataInputStream targetFileStream;
	private static FileWriter hashOutputFile;
	private static SHAHasher hashFunction;
	private static String hash, outputString;
	/**
	 * main function of the program.
	 * handles the creation of the input stream,creation of
	 * the hashing object and the output of the hash
	 *
	 * 
	 * @param args command line argument array
	 * @throws Exception
	 */
	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws Exception {
		
		
		System.out.println("SHA-256 Message Digest Generator\nBen Roberts 2012");
		//check for command line arguments
		if (args.length > 0) { 
			try {
				//hash input handling
				try{
					targetFilePath = Paths.get(args[0]);
					targetFileLength = Files.size(targetFilePath);
					System.out.println("File path: " + targetFilePath.toString());
					System.out.println("File Size (bytes): " + targetFileLength.byteValue());
					System.out.println("Opening filestreams to " + targetFilePath.toString() + " and " + targetFilePath.toString()+".SHA256");
				
					targetFileStream = new DataInputStream( new BufferedInputStream( new FileInputStream(targetFilePath.toString())));
					
				} catch(InvalidPathException|NoSuchFileException e) {
					targetFileLength = (long) args[0].getBytes().length;
					System.out.println("Provided String: " + args[0]);
					System.out.println("String Size (bytes): " + targetFileLength);
					targetFileStream = new DataInputStream(new StringBufferInputStream(args[0]));
				}
				
				hashOutputFile = new  FileWriter(targetFilePath.toString()+".SHA256.txt");
				System.out.println("File streams opened. Starting Hash function");
				hashFunction = new SHA256Hasher(targetFileStream,targetFileLength);
				hashFunction.operationTests(4);
				
				long time = System.nanoTime();
				hash = hashFunction.computeHash();
				time = System.nanoTime() - time;
				outputString = "Computed Hash: " + hash;
				
				if((args.length > 1) && args[1].length() == 64) {
 					outputString += (System.getProperty("line.separator") + "Reference Hash: " + args[1]);
 					if(args[1].contains(hash)) {
 						outputString +=(System.getProperty("line.separator") + "Hashes match, Integrity check passed.");
 					} else {
 						outputString += (System.getProperty("line.separator") + "Hashes do not match, Integrity check failed.");
 					}
				} else if (args.length > 1) {
					System.out.println("Provided reference hash is of incorrect length.");
				}
				outputString += (System.getProperty("line.separator") + "Execution time: " + Float.toString(time/(1e9f)) + "s");
				
				System.out.println(outputString);
				hashOutputFile.write(outputString);
				targetFileStream.close();
				hashOutputFile.close();
				
				} catch(Exception e) {	
					e.printStackTrace();
				}
			
		}
		else {
			System.out.println("Commandline Argument Error.");
		}
	}

}
