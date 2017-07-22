package com.ahmadsaleh.bitcoinkeys;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.UnsupportedEncodingException;
import java.security.*;

/**
 * Created by Ahmad Y. Saleh on 7/18/17.
 */
public final class ECDSAEncryptionUtils {

    private ECDSAEncryptionUtils() {
        throw new UnsupportedOperationException("utility class is not supposed to be used this way!");
    }

    public static KeyPair generateKeyPair(){
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
            g.initialize(ecSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Error while generating cryptographic keys!", e);
        }
    }

    public static byte[] sign(String plainText, PrivateKey privateKey) {
        if(plainText == null){
            throw new IllegalArgumentException("plainText cannot be null");
        }
        if(privateKey == null){
            throw new IllegalArgumentException("privateKey cannot be null");
        }
        try {
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(plainText.getBytes("UTF-8"));
            return ecdsaSign.sign();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | SignatureException | InvalidKeyException e) {
            throw new IllegalStateException("Error while signing text!", e);
        }
    }

    public static boolean verify(String plainText, byte[] signature, PublicKey publicKey) {
        if(plainText == null){
            throw new IllegalArgumentException("plainText cannot be null");
        }
        if(signature == null || signature.length == 0){
            throw new IllegalArgumentException("signature cannot be null nor empty");
        }
        if(publicKey == null){
            throw new IllegalArgumentException("publicKey cannot be null");
        }
        try {
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(plainText.getBytes("UTF-8"));
            return ecdsaVerify.verify(signature);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | SignatureException | InvalidKeyException e) {
            throw new IllegalStateException("Error while verifying signature!", e);
        }
    }
}
