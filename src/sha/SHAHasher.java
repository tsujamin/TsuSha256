package sha;
/**
 * Common interface used by implemented TsuSHA hashers
 * 
 * @author Benjamin
 * @vesrion 0.1.1
 */
public interface SHAHasher {
	/**
	 * Message Digest computing function
	 * 
	 * 
	 * @return String the messageDigest of the input in hex 
	 * @throws Exception
	 */
	public String computeHash();
	public void operationTests(int word);
}
