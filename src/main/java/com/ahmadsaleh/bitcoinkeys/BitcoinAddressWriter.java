package com.ahmadsaleh.bitcoinkeys;

import org.bitcoinj.core.Base58;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Created by Ahmad Y. Saleh on 7/20/17.
 */
public class BitcoinAddressWriter extends BufferedWriter {

    private static final byte MAIN_BITCOIN_NETWORK_VERSION = 0x00;

    public BitcoinAddressWriter(Writer writer) {
        super(writer);
    }

    public void write(PublicKey publicKey) throws IOException {
        byte[] sha256Hash = sha256Hash(asByteArray(publicKey));
        byte[] ripemd160Hash = ripemd160Hash(sha256Hash);
        byte[] versioned = addVersion(ripemd160Hash, MAIN_BITCOIN_NETWORK_VERSION);
        byte[] firstSha256Hash = sha256Hash(versioned);
        byte[] secondSha256Hash = sha256Hash(firstSha256Hash);
        byte[] checkSum = Arrays.copyOfRange(secondSha256Hash, 0, 4);
        byte[] address = join(versioned, checkSum);
        String base58Address = Base58.encode(address);
        write(base58Address);
    }

    private byte[] asByteArray(PublicKey publicKey) {
        try {
            ECPublicKeyParameters ecPublicKeyParameters
                    = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
            return ecPublicKeyParameters.getQ().getEncoded(false);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Error while converting key!", e);
        }
    }

    private byte[] join(byte[] firstPart, byte[] secondPart) {
        byte[] result = new byte[firstPart.length + secondPart.length];
        System.arraycopy(firstPart, 0, result, 0, firstPart.length);
        System.arraycopy(secondPart, 0, result, firstPart.length, secondPart.length);
        return result;
    }

    private byte[] sha256Hash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error while hashing data", e);
        }
    }

    private byte[] ripemd160Hash(byte[] data) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(data, 0, data.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    private byte[] addVersion(byte[] data, byte version) {
        byte[] result = new byte[data.length + 1];
        System.arraycopy(data, 0, result, 1, data.length);
        result[0] = version;
        return result;
    }
}
