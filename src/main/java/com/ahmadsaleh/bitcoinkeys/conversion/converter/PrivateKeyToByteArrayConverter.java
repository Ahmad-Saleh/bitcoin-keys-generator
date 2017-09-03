package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.conversion.ConversionException;
import org.bitcoinj.core.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class PrivateKeyToByteArrayConverter implements TypeConverter<BCECPrivateKey, byte[]> {

    @Override
    public byte[] convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof BCECPrivateKey)) {
            throw new IllegalArgumentException("expected org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey but found " + object.getClass().getName());
        }

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(Utils.bigIntegerToBytes(((BCECPrivateKey) object).getS(), 32));
            return baos.toByteArray();
        } catch (IOException e) {
            throw new ConversionException("Error while converting private key to byte array!", e);
        }
    }

    @Override
    public Class<BCECPrivateKey> getFromType() {
        return BCECPrivateKey.class;
    }

    @Override
    public Class<byte[]> getToType() {
        return byte[].class;
    }
}
