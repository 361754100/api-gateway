package com.hro.core.apigateway.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 生成、还原 RSA公钥私钥 对的工具类
 * 
 * RSA是目前最有影响力的公钥加密算法，该算法基于一个十分简单的数论事实：
 * 将两个大素数相乘十分容易，但那时想要对其乘积进行因式分解却极其困难，因此可以将乘积公开作为加密密钥，即公钥，而两个大素数组合成私钥。
 * 公钥是可发布的供任何人使用，私钥则为自己所有，供解密之用。
 * 
 * RSA算法实现过程中提到(N,e)是公钥，(N,d)是私钥。既然已经获取到了PublicKey和PrivateKey了，那如何取到N、e、d这三个值呢。
 * 要取到这三个值，首先要将PublicKey和PrivateKey强制转换成RSAPublicKey和RSAPrivateKey。共同的N值可以通过getModulus()获取。
 * 执行RSAPublicKey.getPublicExponent()可以获取到公钥中的e值，执行RSAPrivateKey.getPrivateExponent()可以获取私钥中的d值。
 * 
 * 由于程序中动态生成KeyPair对明文加密后生成的密文是不可测的，所以在实际开发中通常在生成一个KeyPair后将公钥和私钥的N、e、d这三个特征值记录下来，在真实的开发中使用这三个特征值再去将PublicKey和PrivateKey还原出来。
 * 
 * @author Mojianzhang
 *
 */
public class RsaUtil {
	
	public static final String KEY_ALGORITHM = "RSA";
	private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

	private static final String PRIVATE_MODULUS = "OTg0NzgwOTQzOTQzNjEzMjUzODg5MTE3NjA1MDc3NjAzMDAzNjcwMTYxNzExNzYxNjEwMDM4MzAxNjg1NDgzNzQ5ODk3NzQ4OTc4NTYyMDIxOTc2MzEyNzM2MDEwMDc0MzgwNjE4NDk1MjU0MzU1MDkyNDE0MzUzMzM0MzQ1MDUwNzkxODE2MDEyMzg3ODcyNTc3OTcwOTc0NDM1OTYyNDc0NDAzNDM0Njc1MjU5ODE0OTY5MzU2OTIwNjE2NDM2NzE4NzQwNjA5MTUyMjg3OTAxODEyODM5ODIzODYzMDE2ODg5MzI4MDUwMTg4NDQ2MDg2NTY3Mzk5OTA3NDM0NDA0MTE0NDUyMTExNjcxNzUyNzczNTEyMTc2MDY0MjkxNzg1NjM4MTA1MzcyMDM1NTczMjk=";
	private static final String PRIVATE_EXPONENT = "NTQ3ODkwMjQxODE4Njk4MjM4NjAyNjk3ODA2MDY4OTMxNDU0MjkwMjcwMTczMDk2OTA0NDIzNzA4MDc0MTU4MjM4Njg2MTEyMDE2OTcyNTI2MTM0ODU5OTI2MTU0NjgxMDUxNDA3Nzc4NDE0NzAxNTQ4NDMyMzY4NzU3NzUzNDcxMTk5MDM1NTg5NzIzMTU4MDYyNDM3NjcxMjc3Njc4MTk0MzcxNDA4MzIwODQ0NDI3MDE2MTgxMjUyNjk5ODY5NjU5Mzk3MDU5NzIyNzg1NTE0ODAwMjg1MTIwMDE5MzY3NzgzMjY5NDI0Mzc2ODEzNDA5NjA1NDQ1MTU3NDEyOTAzNjE3MTEyNDM2MTYwOTkwMTEyMTQ5ODg5OTU5MDIwNDQ0NzcyMDMyMjY2MTIxNDM2NDk=";

    private static Logger logger = LoggerFactory.getLogger(RsaUtil.class);
    
    /**
     * 获得公钥
     * 
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        //获得map中的公钥对象 转为key对象
    	RSAPublicKey key = (RSAPublicKey) keyMap.get(PUBLIC_KEY);
    	logger.info("public modulus ="+ key.getModulus() + " exponent ="+ key.getPublicExponent());

    	String base64_modulus = RsaUtil.encryptBASE64(StringUtils.toString(key.getModulus()).getBytes("UTF-8"));
		String base64_exponent = RsaUtil.encryptBASE64(StringUtils.toString(key.getPublicExponent()).getBytes("UTF-8"));
		logger.info("Base64 public modulus ="+ base64_modulus + " exponent ="+ base64_exponent);
        //编码返回字符串
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 获得私钥
     * 
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        //获得map中的私钥对象 转为key对象
    	RSAPrivateKey key = (RSAPrivateKey) keyMap.get(PRIVATE_KEY);
    	logger.info("private modulus ="+ key.getModulus() + " exponent ="+ key.getPrivateExponent());

		String base64_modulus = RsaUtil.encryptBASE64(StringUtils.toString(key.getModulus()).getBytes("UTF-8"));
		String base64_exponent = RsaUtil.encryptBASE64(StringUtils.toString(key.getPrivateExponent()).getBytes("UTF-8"));
		logger.info("Base64 private modulus ="+ base64_modulus + " exponent ="+ base64_exponent);
        //编码返回字符串
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 解码返回byte
     * 
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
        return Base64.getDecoder().decode(key);
    }

    /**
     * 编码返回字符串
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key) throws Exception {
        return new String(Base64.getEncoder().encode(key), "UTF-8");
    }
    
    /**
     * map对象中存放公私钥
     * 
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        //获得对象 KeyPairGenerator 参数 RSA 1024个字节
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        //通过对象 KeyPairGenerator 获取对象KeyPair
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        //通过对象 KeyPair 获取RSA公私钥对象RSAPublicKey RSAPrivateKey
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        //公私钥对象存入map中
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }
    
    /**
     * 使用指定的公钥加密数据。
     * 
     * @param pubKey 给定的公钥。
     * @param data 要加密的数据。
     * @return 加密后的数据。
     */
 	public static byte[] encryptData(byte[] data, PublicKey pubKey) {
 		try {
 			Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
 			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
 			return cipher.doFinal(data);
 		} catch (Exception e) {
			logger.error("======error======", e);
 			return null;
 		}
 	}
    
    /**
     * 使用指定的私钥解密数据。
     * 
     * @param privateKey 给定的私钥。
     * @param data 要解密的数据。
     * @return 原数据。
     */
    public static byte[] decryptData(byte[] data, PrivateKey privateKey) {
        try {
        	Cipher ci = Cipher.getInstance(KEY_ALGORITHM);
            ci.init(Cipher.DECRYPT_MODE, privateKey);
            return ci.doFinal(data);
		} catch (Exception e) {
			logger.error("======error======", e);
			return null;
		}
    }

	/**
	 * 使用指定的私钥解密数据。
	 *
	 * @param data 要解密的数据。
	 * @return 原数据。
	 */
	public static byte[] decryptData(byte[] data) {
		try {
			//1.根据 N、E、D值还原 公钥
			String modulus_str = new String(Base64.getDecoder().decode(PRIVATE_MODULUS.getBytes("UTF-8")));
			String exponent_str = new String(Base64.getDecoder().decode(PRIVATE_EXPONENT.getBytes("UTF-8")));
			PrivateKey privateKey = RsaUtil.restorePrivateKey(modulus_str, exponent_str);

			Cipher ci = Cipher.getInstance(KEY_ALGORITHM);
			ci.init(Cipher.DECRYPT_MODE, privateKey);
			return ci.doFinal(data);
		} catch (Exception e) {
			logger.error("======error======", e);
			return null;
		}
	}
    
    /**
     * 根据N、E值 还原公钥
     * 
     * @param modulus
     * @param publicExponent
     * @return
     */
    public static PublicKey restorePublicKey(String modulus, String publicExponent) {
    	PublicKey pubKey = null;
    	try {
    		BigInteger bigIntModulus = new BigInteger(modulus);
    		BigInteger bigIntPrivateExponent = new BigInteger(publicExponent);
    		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
    		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    		pubKey = keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			logger.error("======error======", e);
		}
    	return pubKey;
    }
    
    /**
     * 根据N、D值 还原私钥
     * 
     * @param modulus
     * @param privateExponent
     * @return
     */
    public static PrivateKey restorePrivateKey(String modulus, String privateExponent) {
    	PrivateKey priKey = null;
    	try {
    		BigInteger bigIntModulus = new BigInteger(modulus);
    		BigInteger bigIntPrivateExponent = new BigInteger(privateExponent);
    		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(bigIntModulus, bigIntPrivateExponent);
    		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    		priKey = keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			logger.error("======error======", e);
		}
    	return priKey;
    }
    
    
    public static void main(String[] args) {
    	try {
			/*
			// 以下逻辑用于生成 公钥和私钥，便于理解RSA 的工作原理(没问题的)
			//1.生成 公钥+私钥 对
			Map<String, Object> keyMap = RsaUtil.initKey();
    		String publicKey = RsaUtil.getPublicKey(keyMap);
    		String privateKey = RsaUtil.getPrivateKey(keyMap);
    		
    		RSAPublicKey pubKey = (RSAPublicKey) keyMap.get("RSAPublicKey");
    		RSAPrivateKey priKey = (RSAPrivateKey) keyMap.get("RSAPrivateKey");
    		
    		//2.使用公钥 进行数据加密、私钥进行数据解密
    		String clientData = "Oh my God!";
    		//--加密数据
    		String encryDatas = Base64.getEncoder().encodeToString(RsaUtil.encryptData(clientData.getBytes(), pubKey));
    		//--解密数据
    		String decryDatas = new String(RsaUtil.decryptData(Base64.getDecoder().decode(encryDatas), priKey));
    		
    		logger.info("public Key = "+ publicKey  +", private Key = " + privateKey);
    		logger.info("clientData = "+ clientData +", encryDatas = "+ encryDatas +", decryDatas = " + decryDatas);
    		
    		//3.根据 N、E、D值还原 公钥+私钥 对
//    		PublicKey pubKey2 =  RsaUtil.restorePublicKey(String.valueOf(pubKey.getModulus()), String.valueOf(pubKey.getPublicExponent()));
    		PrivateKey priKey2 = RsaUtil.restorePrivateKey(String.valueOf(priKey.getModulus()), String.valueOf(priKey.getPrivateExponent()));
    		String decryDatas2 = new String(RsaUtil.decryptData(Base64.getDecoder().decode(encryDatas), priKey2));
    		
    		String publicKey2 = RsaUtil.encryptBASE64(RsaUtil.restorePublicKey(String.valueOf(pubKey.getModulus()), String.valueOf(pubKey.getPublicExponent())).getEncoded());
    		String privateKey2 = RsaUtil.encryptBASE64(RsaUtil.restorePrivateKey(String.valueOf(priKey.getModulus()), String.valueOf(priKey.getPrivateExponent())).getEncoded());
		
    		logger.info("public Key2 = "+ publicKey2  +", private Key2 = " + privateKey2 +", decryDatas2 = "+ decryDatas2);
			*/



			String encryDatas = "bGQKU8h9q/xzZi4KJb6tFiVCD2rnAACIO4s7vvyoeDV43Bz+FBWuSYEA4bphIb53kt8UE9DHHpAiYxSuNm5vB3Hct3tY8AbpBJ3LCtXLRxpZIOiP3RGIGBMX8/XcECinaTLmRJJZHtvDEeoZSDV70qzA9JrILI3k1f4O7JAIgrM=";
			//--解密数据
			String decryDatas = new String(RsaUtil.decryptData(Base64.getDecoder().decode(encryDatas)));

			logger.info("decryDatas = "+ decryDatas);

    	} catch (Exception e) {
			e.printStackTrace();
		}
    }
}
