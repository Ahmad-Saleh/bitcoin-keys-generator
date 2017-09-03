package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.KeysConversionUtils;
import org.bitcoinj.core.Base58;

import java.security.PrivateKey;

import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.addToStart;
import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.copyOfRange;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.sha256Hash;
import static com.google.common.primitives.Bytes.concat;

public class PrivateKeyToWifConverter implements TypeConverter<PrivateKey, String> {

    private static final byte MAIN_BITCOIN_NETWORK_VERSION = (byte) 0x80;

    @Override
    public String convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof PrivateKey)) {
            throw new IllegalArgumentException("expected java.security.PrivateKey but found " + object.getClass().getName());
        }

        byte[] versioned = addToStart(KeysConversionUtils.asByteArray((PrivateKey) object), MAIN_BITCOIN_NETWORK_VERSION);
        byte[] firstSha256Hash = sha256Hash(versioned);
        byte[] secondSha256Hash = sha256Hash(firstSha256Hash);
        byte[] checkSum = copyOfRange(secondSha256Hash, 0, 4);
        byte[] wif = concat(versioned, checkSum);
        return Base58.encode(wif);
    }

    @Override
    public Class<PrivateKey> getFromType() {
        return PrivateKey.class;
    }

    @Override
    public Class<String> getToType() {
        return String.class;
    }
}
