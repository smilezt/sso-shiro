package com.test.shiro.utils;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class Key {
    /**
     * 随机生成秘钥
     */
    public static byte[] getCipherKey() {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to acquire AES algorithm.This is required to function.";
            throw new IllegalStateException(msg, e);
        }
        kg.init(128);
        SecretKey sk =  kg.generateKey();
        byte[] cipherKey = sk.getEncoded();
            return cipherKey;
    }

}
