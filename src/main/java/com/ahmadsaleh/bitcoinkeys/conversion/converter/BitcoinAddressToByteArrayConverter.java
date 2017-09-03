package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.ByteArrayUtils;
import com.ahmadsaleh.bitcoinkeys.KeysConversionUtils;
import com.ahmadsaleh.bitcoinkeys.conversion.ConversionException;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.addToStart;
import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.copyOfRange;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.ripemd160Hash;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.sha256Hash;
import static com.google.common.primitives.Bytes.concat;

public class BitcoinAddressToByteArrayConverter implements TypeConverter<String, byte[]> {

    @Override
    public byte[] convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof String)) {
            throw new IllegalArgumentException("expected String but found " + object.getClass().getName());
        }

        try {
            byte[] decoded = Base58.decode((String) object);
            return ByteArrayUtils.copyOfRange(decoded, 1, decoded.length - 4);
        } catch (AddressFormatException e) {
            throw new ConversionException("Error while decoding Base58", e);
        }
    }

    @Override
    public Class<String> getFromType() {
        return String.class;
    }

    @Override
    public Class<byte[]> getToType() {
        return byte[].class;
    }
}
