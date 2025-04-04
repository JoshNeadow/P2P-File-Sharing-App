package com.group12.p2p_file_sharing.crypto;

import javax.crypto.Cipher;

import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaUtils {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048; // recommended for security

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        KeyPair pair = keyGen.generateKeyPair();
        return pair;
    }

    // convert Base64 public key to correct type
    public static PublicKey getPublicKeyFromBase64(String base64Key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key); // Decode Base64 string
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Use RSA algorithm
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    // encrypt with public key
    public static byte[] encryptFile(File file, PublicKey publicKey) throws Exception {
        byte[] data = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // decrypt with private key
    public static byte[] decryptFile(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    // Deserialize strings to keys
    // public static PublicKey publicKeyFromString(String keyStr) throws Exception {
    // byte[] keyBytes = Base64.getDecoder().decode(keyStr);
    // X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    // return KeyFactory.getInstance(ALGORITHM).generatePublic(spec);
    // }

    // public static PrivateKey privateKeyFromString(String keyStr) throws Exception
    // {
    // byte[] keyBytes = Base64.getDecoder().decode(keyStr);
    // PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    // return KeyFactory.getInstance(ALGORITHM).generatePrivate(spec);
    // }
}
