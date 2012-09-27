package sha;

import java.io.*;
import java.util.Arrays;

/**
 * Class for generation of the SHA-2 (256) Message Digests of a 
 * DataInputStream.
 * 
 * @author Benjamin Roberts
 * @version 0.1.1
 * 
 */
public class SHA256Hasher implements SHAHasher {

	
	private DataInputStream messageStream;
	private int lastBlockLength;
	private long messageKBitCount;
	private long messageBlockNumber;
	private int[] tempVariables = new int[2];
	private int[] workingVariables = new int[8];
	private int[] messageSchedule = new int[64];
	private boolean dualFinalBlock;
	private boolean[][] finalBlock = new boolean[2][512];
	private String lengthBinary;
	private String tempString;
	private String messageDigest;
	/**
	 * array of word constants used by the algorithm
	 * made up of the first 32 bits of the fractional parts, 
	 * of the cube roots of the first 64 prime numbers in order
	 */
	private int[] K256 = {	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
							0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
							0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
							0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
							0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
							0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
							0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
							0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
	/**
	 * word array of the initial hash value 
	 * made up of the first 32 bits, of the fractional parts, 
	 * of the square roots of the first 8 prime numbers in order
	 */
	private int[] hash = { 	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }; 
	
	
	/**
	 * constructor of the SHA256Hasher class
	 * stores the input stream and formats the final message blocks
	 * 
	 * @param messageStream the file of which's message digest is generated
	 * @param messageLength length of the message in bytes
	 * @see java.io.DataInputStream
	 */
	public SHA256Hasher(DataInputStream messageStream, long messageLength)
	{
		messageLength = messageLength * 8; //convert from byte to bit length
		this.messageStream = messageStream;
		/*
		 * creates the final message blocks
		 * determines length of padding required, kBitLength, and therefore number of padded blocks
		 * appends the 64bit messageLength string to the final block
		 */
		messageKBitCount = computeKBits(messageLength);
		lastBlockLength = (int) messageLength%512;
		System.out.println("Length of Last Block: " + lastBlockLength);
		System.out.println("number of K bits: " + messageKBitCount);
		if (messageKBitCount <= 447) { //final block can fit last message, appended 1 and appended length
			messageBlockNumber = 1+(messageLength/512); //will round down ignoring end of message
			dualFinalBlock = false;
		} else {  //two padded final blocks needed to store message, 1 and length
			messageBlockNumber = 2+(messageLength/512);
			dualFinalBlock = true;
		}
		System.out.println("Does the message have 2 final padded blocks? " + Boolean.toString(dualFinalBlock));
		lengthBinary = Long.toBinaryString(messageLength);
		System.out.println("Value of Length String in binary: " + lengthBinary);
		for (int i = 0; i<lengthBinary.length(); i++) {
			finalBlock[1][511-i] = (lengthBinary.charAt((lengthBinary.length()-i)-1) == '1') ? true:false;
		}
	}
	/**
	 * Message Digest computing function
	 * handles creation of final block (in a very bloated way)
	 * and computation of the final value
	 * 
	 * @return String the messageDigest of the input in hex 
	 * @throws Exception
	 */
	public String computeHash() {
		try {
			for(int i = 1; i<=(messageBlockNumber) ; i++) {
				//System.out.println("Processing Block Number: " + i);
				/*
				 * If two-final-block scenario, end of message is placed in 2nd last block, processed, 
				 * then the block with appended length is processed, otherwise the end of the message 
				 * is read into the same block as the appended length
				 * all other blocks processed as normal
				 */
				if ((i == (messageBlockNumber-1)) && (dualFinalBlock)) {
					/*
					 * long slow method of reading each byte of the stream into the final-block
					 * accessing the individual bits of the byte would be more efficient but impossible?
					 */
					for(int j = 1; j <= (lastBlockLength/8); j++) {
						tempString = Integer.toBinaryString(Integer.parseInt(Byte.toString(messageStream.readByte())));
						for(int k = 0; k < tempString.length(); k++) {
							finalBlock[0][j*8-(1+k)] = (tempString.charAt(tempString.length()-(k+1)) == '1') ? true:false;
						}
					}
					finalBlock[0][lastBlockLength] = true; //append 1 to the end of message
					for(int t = 0; t < 16; t++) {
						messageSchedule[t] = boolArrayToInt(finalBlock[0],(t*32)); //read word sequence from 2nd last block into schedule
					}
					
					
				} else if ((i == messageBlockNumber) && dualFinalBlock) {
					for(int t = 0; t < 16; t++) {
						messageSchedule[t] = boolArrayToInt(finalBlock[1],(t*32)); //read final block into schedule
					}						
				} else if((i == messageBlockNumber) && (messageKBitCount == 447)) {
					finalBlock[1][0] = true;
					for(int t = 0; t < 16; t++) {
						messageSchedule[t] = boolArrayToInt(finalBlock[1],(t*32)); //read word sequence from 2nd last block into schedule
					}
				} else if (i == messageBlockNumber) {
					for(int j = 1; j <= (lastBlockLength/8); j++) {
						tempString = Integer.toBinaryString(Integer.parseInt(Byte.toString(messageStream.readByte())));
						for(int k = 0; k < tempString.length(); k++) {
							finalBlock[1][j*8-(1+k)] = (tempString.charAt(tempString.length()-(k+1)) == '1') ? true:false;
						}
					finalBlock[1][lastBlockLength] = true;
					}
					//write to schedule
					for(int t = 0; t < 16; t++) {
						messageSchedule[t] = boolArrayToInt(finalBlock[1],(t*32));
					}
				} else {
					for(int t = 0; (t < 16); t++) {
						messageSchedule[t] = messageStream.readInt(); //read words of next message block into schedule
					}
				}
	
				for(int t = 16; t < 64; t++) { //fill schedule as dictated by SHA-2
					messageSchedule[t] = lowerSigma256_1(messageSchedule[t-2]) + messageSchedule[t-7] 
									   + lowerSigma256_0(messageSchedule[t-15]) + messageSchedule[t-16];
				}
				
				/*
				 * SHA256 Hash function
				 * Refer to http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf for more details
				 */
				workingVariables = Arrays.copyOf(hash,8); //last hashes into working variables 
				
				//operation loop
				for(int t = 0;t < 64; t++) {
					tempVariables[0] = workingVariables[7] + upperSigma256_1(workingVariables[4])
									 + ch(workingVariables[4], workingVariables[5], workingVariables[6])
									 + K256[t] + messageSchedule[t];
					tempVariables[1] = upperSigma256_0(workingVariables[0])
									 + maj(workingVariables[0], workingVariables[1], workingVariables[2]);
					for(int j = 7; j > 0; j--) {
						workingVariables[j] = workingVariables[j-1];
					}				
					workingVariables[4] += tempVariables[0];
					workingVariables[0] = tempVariables[0] + tempVariables[1];
				}
					
				for(int t=0;t < 8; t++) { //store intermediate hashes
					hash[t] += workingVariables[t];
				}
			}
			messageDigest = "";
			for(int i = 0; i<8; i++) { //concatenate hash
				if (Integer.toHexString(hash[i]).length() < 8)
				{
					//append each 8 hex character partial hash to the messageDigest
					for(int j = 1; j <= (8-(Integer.toHexString(hash[i]).length())); j++) {
							messageDigest += "0";
					}
					messageDigest+=Integer.toHexString(hash[i]);
				} else {
					messageDigest+=Integer.toHexString(hash[i]);
				}
			}
			return messageDigest;
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}
	
	
	/*
	 * the 6 operations of SHA-2 (256)
	 */
	private int upperSigma256_0(int x){
		return (	((x>>>2) ^ (x<<30))		^		((x>>>13) ^ (x<<19))			^		((x>>>22)	^	(x<<10)));
	}
	private int upperSigma256_1(int x){
		return (	((x>>>6) ^ (x<<26))		^		((x>>>11) ^ (x<<21))			^		((x>>>25)	^	(x<<7)));
	}
	private int lowerSigma256_0(int x){
		return (	((x>>>7) ^ (x<<25))		^		((x>>>18) ^ (x<<14))			^		(x>>>3));
	}
	private int lowerSigma256_1(int x){
		return (	((x>>>17) ^ (x<<15))		^		((x>>>19) ^ (x<<13))			^		(x>>>10));
	}
	private int ch(int x, int y, int z) {
		return (((x&y)	^	((~x)&z)));
		}
	private int maj(int x, int y, int z) {
		return ((x&y)	^	(x&z)	^	(y&z));	
	}
	
	/**
	 * computes the number of kBits, or length of 0b0 padding required
	 * by the message
	 * 
	 * @param messageLength length of message in bits
	 * @return 				the number of kBits
	 */
	private long computeKBits(long messageLength)
	{
		long k = 0;
		while((messageLength + 1 + k)%512 != 448) {
			k++;
		}
		return k;
	}
	
	/**
	 * converts a 32bit segment of a bit(boolean) array to an integer
	 * assumes array is big endian
	 *  
	 * @param boolArray one-dimensional bit array
	 * @param start index of array from which an integer should be read
	 * @return
	 */
	int boolArrayToInt(boolean[] boolArray, int start) {
		int result = 0;
		for(int i = start;i < start+32; i++) {
			if (boolArray[i]) {
				result++;
			}
			if(i!= start+31) {
				result = result << 1;
			}
		}
		return result;
	}
	/**
	 * Used to test the outputs of each operation function and check their
	 * correct operation
	 * 
	 * @deprecated all operator functions are correct as of v0.1.0
	 * @param word 	an integer used to as a sample
	 */
	public void operationTests(int word) {
		System.out.println("SHA-256 Operation Function Test:");
		System.out.println("Supplied word: " + Integer.toHexString(word));
		System.out.println("upperSigma256_0: " + Integer.toString(upperSigma256_0(word)));
		System.out.println("upperSigma256_1: " + Integer.toString(upperSigma256_1(word)));
		System.out.println("lowerSigma256_0: " + Integer.toString(lowerSigma256_0(word)));
		System.out.println("lowerSigma256_1: " + Integer.toString(lowerSigma256_1(word)));
		System.out.println("The parameters of the following operations (x,y and z) are: " + Integer.toString(word) + ", " 
										+ Integer.toString(word+1) + " and " + Integer.toString(word+2) + " respectivly");
		System.out.println("ch: " + Integer.toString(ch(word,word+1,word+2)));
		System.out.println("maj: " + Integer.toString(maj(word,word+1,word+2)));
		
		boolean[] testArray = new boolean[32];
		String wordBinary;
		wordBinary = Integer.toBinaryString(word);

		for (int i = 0; i<wordBinary.length(); i++) {
			testArray[31-i] = (wordBinary.charAt((wordBinary.length()-i)-1) == '1') ? true:false;
		}
		System.out.println("Result of long -> bool[] -> long operation: " + Integer.toString(boolArrayToInt(testArray,0)));
	}
}
