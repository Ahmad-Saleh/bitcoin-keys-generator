package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.conversion.ConversionException;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

public class ByteArrayToPrivateKeyConverter implements TypeConverter<byte[], PrivateKey> {

    @Override
    public PrivateKey convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof byte[])) {
            throw new IllegalArgumentException("expected byte[] but found " + object.getClass().getName());
        }

        X9ECParameters ecCurve = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256k1");
        java.security.spec.ECParameterSpec ecParameterSpec = new ECNamedCurveSpec("secp256k1", ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, (byte[]) object), ecParameterSpec);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ConversionException("Error while building key!", e);
        }
    }

    @Override
    public Class<byte[]> getFromType() {
        return byte[].class;
    }

    @Override
    public Class<PrivateKey> getToType() {
        return PrivateKey.class;
    }
}
