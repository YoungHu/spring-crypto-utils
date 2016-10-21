package com.springcryptoutils.core.cipher.asymmetric;

import com.springcryptoutils.core.cipher.Mode;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;

/**
 * @author huyong
 * @version 1.0.0
 * @description
 * @date 2016/10/21 17:59
 */
public class CipherHelper {
	/**
	 * encrpty plain text byte
	 *
	 * @param provider  algorithm provider
	 * @param algorithm algorithm
	 * @param mode      algorithm mode
	 * @param key       private key
	 * @param keyLength RSA key length
	 * @param message   plain text as byte array
	 * @return encrypt byte array
	 */
	public static byte[] crypt(String provider, String algorithm, Mode mode, Key key, int keyLength, byte[] message) {
		try {
			final Cipher cipher;
			int encryptLength = keyLength / 8 - 11;
			int decryptLength = keyLength / 8;
			int tempLength;

			if (null == provider || provider.length() == 0) {
				cipher = Cipher.getInstance(algorithm);
			} else {
				cipher = Cipher.getInstance(algorithm, provider);
			}
			switch (mode) {
				case ENCRYPT:
					cipher.init(Cipher.ENCRYPT_MODE, key);
					tempLength = encryptLength;
					break;
				case DECRYPT:
					cipher.init(Cipher.DECRYPT_MODE, key);
					tempLength = decryptLength;
					break;
				default:
					throw new AsymmetricEncryptionException("error encrypting/decrypting message: invalid mode; mode=" + mode);
			}

			int nBlock = (message.length / tempLength);
			if ((message.length % tempLength) != 0) {
				nBlock += 1;
			}
			if (message.length > tempLength) {
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream(nBlock * (mode == Mode.DECRYPT ? encryptLength : decryptLength));
				for (int offset = 0; offset < message.length; offset += tempLength) {
					int inputLen = (message.length - offset);
					if (inputLen > tempLength) {
						inputLen = tempLength;
					}
					byte[] encryptedBlock = cipher.doFinal(message, offset, inputLen);
					outputStream.write(encryptedBlock);
				}
				outputStream.flush();
				outputStream.close();
				return outputStream.toByteArray();
			} else {
				return cipher.doFinal(message);
			}
		} catch (Exception e) {
			throw new AsymmetricEncryptionException("error encrypting/decrypting message; mode=" + mode, e);
		}
	}

	public static String b64crypt(String provider, String algorithm, Mode mode, Key key, int keyLength, String message,
	                              String charset) {
		try {
			switch (mode) {
				case ENCRYPT:
					byte[] result = crypt(provider, algorithm, mode, key, keyLength, message.getBytes(charset));
					return Base64.encodeBase64String(result);
				case DECRYPT:
					byte[] result2 = crypt(provider, algorithm, mode, key, keyLength, Base64.decodeBase64(message));
					return new String(result2, charset);
				default:
					throw new AsymmetricEncryptionException("error encrypting/decrypting message: invalid mode; mode=" + mode);
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}
}
