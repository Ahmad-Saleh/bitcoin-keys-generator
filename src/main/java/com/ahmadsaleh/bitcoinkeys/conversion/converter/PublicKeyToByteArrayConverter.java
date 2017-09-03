package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.conversion.ConversionException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PublicKeyToByteArrayConverter implements TypeConverter<PublicKey, byte[]> {

    @Override
    public byte[] convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof PublicKey)) {
            throw new IllegalArgumentException("expected java.security.PublicKey but found " + object.getClass().getName());
        }

        try {
            ECPublicKeyParameters ecPublicKeyParameters
                    = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter((PublicKey) object);
            return ecPublicKeyParameters.getQ().getEncoded(false);
        } catch (InvalidKeyException e) {
            throw new ConversionException("Error while converting public key to byte array!", e);
        }
    }

    @Override
    public Class<PublicKey> getFromType() {
        return PublicKey.class;
    }

    @Override
    public Class<byte[]> getToType() {
        return byte[].class;
    }
}
