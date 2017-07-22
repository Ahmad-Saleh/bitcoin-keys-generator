package com.ahmadsaleh.bitcoinkeys.writer;

import com.ahmadsaleh.bitcoinkeys.KeysConversionUtils;
import org.bitcoinj.core.Base58;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.PublicKey;

import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.addToStart;
import static com.ahmadsaleh.bitcoinkeys.ByteArrayUtils.copyOfRange;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.ripemd160Hash;
import static com.ahmadsaleh.bitcoinkeys.HashingUtils.sha256Hash;
import static com.google.common.primitives.Bytes.concat;

/**
 * Created by Ahmad Y. Saleh on 7/20/17.
 */
public class BitcoinAddressWriter extends BufferedWriter {

    private static final byte MAIN_BITCOIN_NETWORK_VERSION = 0x00;

    public BitcoinAddressWriter(Writer writer) {
        super(writer);
    }

    public void write(PublicKey publicKey) throws IOException {
        byte[] sha256Hash = sha256Hash(KeysConversionUtils.asByteArray(publicKey));
        byte[] ripemd160Hash = ripemd160Hash(sha256Hash);
        byte[] versioned = addToStart(ripemd160Hash, MAIN_BITCOIN_NETWORK_VERSION);
        byte[] firstSha256Hash = sha256Hash(versioned);
        byte[] secondSha256Hash = sha256Hash(firstSha256Hash);
        byte[] checkSum = copyOfRange(secondSha256Hash, 0, 4);
        byte[] address = concat(versioned, checkSum);
        String base58Address = Base58.encode(address);
        write(base58Address);
    }
}
