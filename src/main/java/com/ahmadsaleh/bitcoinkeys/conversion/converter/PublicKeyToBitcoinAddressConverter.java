package com.ahmadsaleh.bitcoinkeys.conversion.converter;

import com.ahmadsaleh.bitcoinkeys.KeysConversionUtils;
import org.bitcoinj.core.Base58;

import java.security.PrivateKey;
import java.security.PublicKey;

import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.addToStart;
import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.copyOfRange;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.ripemd160Hash;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.sha256Hash;
import static com.google.common.primitives.Bytes.concat;

public class PublicKeyToBitcoinAddressConverter implements TypeConverter<PrivateKey, String> {

    private static final byte MAIN_BITCOIN_NETWORK_VERSION = 0x00;

    @Override
    public String convert(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("cannot convert null!");
        }

        if (!(object instanceof PublicKey)) {
            throw new IllegalArgumentException("expected java.security.PublicKey but found " + object.getClass().getName());
        }

        byte[] sha256Hash = sha256Hash(KeysConversionUtils.asByteArray((PrivateKey) object));
        byte[] ripemd160Hash = ripemd160Hash(sha256Hash);
        byte[] versioned = addToStart(ripemd160Hash, MAIN_BITCOIN_NETWORK_VERSION);
        byte[] firstSha256Hash = sha256Hash(versioned);
        byte[] secondSha256Hash = sha256Hash(firstSha256Hash);
        byte[] checkSum = copyOfRange(secondSha256Hash, 0, 4);
        byte[] address = concat(versioned, checkSum);
        return Base58.encode(address);
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
