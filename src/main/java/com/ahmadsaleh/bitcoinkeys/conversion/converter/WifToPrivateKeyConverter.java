package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.ByteArrayUtils;
import com.ahmadsaleh.bitcoinkeys.KeysConversionUtils;
import com.ahmadsaleh.bitcoinkeys.conversion.ConversionException;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;

import java.security.PrivateKey;
import java.security.PublicKey;

public class WifToPrivateKeyConverter implements TypeConverter<String, PrivateKey> {

    @Override
    public PrivateKey convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof String)) {
            throw new IllegalArgumentException("expected String but found " + object.getClass().getName());
        }

        try {
            byte[] decoded = Base58.decode((String) object);
            byte[] trimmedBytes = ByteArrayUtils.copyOfRange(decoded, 1, decoded.length - 4);
            return KeysConversionUtils.asPrivateKey(trimmedBytes);
        } catch (AddressFormatException e) {
            throw new ConversionException("Error while building private key", e);
        }
    }

    @Override
    public Class<String> getFromType() {
        return String.class;
    }

    @Override
    public Class<PrivateKey> getToType() {
        return PrivateKey.class;
    }
}
