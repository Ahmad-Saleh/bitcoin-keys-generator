package com.ahmadsaleh.bitcoinkeys;

import org.bitcoinj.core.Utils;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

/**
 * Created by Ahmad Y. Saleh on 7/19/17.
 */
public class KeysConversionUtils {

    public static byte[] asByteArray(PublicKey publicKey) {
        try {
            ECPublicKeyParameters ecPublicKeyParameters
                    = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
            return ecPublicKeyParameters.getQ().getEncoded(false);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Error while converting key!", e);
        }
    }

    public static byte[] asByteArray(PrivateKey privateKey) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(Utils.bigIntegerToBytes(((BCECPrivateKey) privateKey).getS(), 32));
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Error while converting key!", e);
        }
    }

    public static PrivateKey asPrivateKey(String hexString) {
        return asPrivateKey(Hex.decode(hexString));
    }

    public static PublicKey asPublicKey(String hexString) {
        return asPublicKey(Hex.decode(hexString));
    }

    public static String asHexString(PrivateKey key) {
        try {
            return new String(Hex.encode(asByteArray(key)), "UTF-8").toUpperCase();
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Error while converting key to hex!", e);
        }
    }

    public static String asHexString(PublicKey key) {
        try {
            return new String(Hex.encode(asByteArray(key)), "UTF-8").toUpperCase();
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Error while converting key to hex!", e);
        }
    }

    public static PrivateKey asPrivateKey(byte[] keyBytes) {
        X9ECParameters ecCurve = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256k1");
        java.security.spec.ECParameterSpec ecParameterSpec = new ECNamedCurveSpec("secp256k1", ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, keyBytes), ecParameterSpec);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Error while building key!", e);
        }
    }

    public static PublicKey asPublicKey(byte[] keyBytes) {
        try {
            ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
            KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
            ECPoint point = ECPointUtil.decodePoint(params.getCurve(), keyBytes);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
            return pk;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Error while building key!", e);
        }
    }

}
