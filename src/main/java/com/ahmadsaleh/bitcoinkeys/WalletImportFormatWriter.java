package com.ahmadsaleh.bitcoinkeys;

import com.google.common.primitives.UnsignedBytes;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * Created by Ahmad Y. Saleh on 7/20/17.
 */
public class WalletImportFormatWriter extends BufferedWriter {

    private static final byte MAIN_BITCOIN_NETWORK_VERSION = (byte) 0x80;

    public WalletImportFormatWriter(Writer writer) {
        super(writer);
    }

    public void write(PrivateKey privateKey) throws IOException {
        byte[] versioned = addVersion(asByteArray(privateKey), MAIN_BITCOIN_NETWORK_VERSION);
        byte[] firstSha256Hash = sha256Hash(versioned);
        byte[] secondSha256Hash = sha256Hash(firstSha256Hash);
        byte[] checkSum = Arrays.copyOfRange(secondSha256Hash, 0, 4);
        byte[] wif = join(versioned, checkSum);
        String base58Wif = Base58.encode(wif);
        write(base58Wif);
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

    private byte[] addVersion(byte[] data, byte version) {
        byte[] result = new byte[data.length + 1];
        System.arraycopy(data, 0, result, 1, data.length);
        result[0] = version;
        return result;
    }

    private byte[] asByteArray(PrivateKey privateKey) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(Utils.bigIntegerToBytes(((BCECPrivateKey) privateKey).getS(), 32));
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Error while converting key!", e);
        }
    }

    public static void main(String[] args) throws IOException {
        StringWriter stringWriter = new StringWriter();
        new WalletImportFormatWriter(stringWriter).write(KeysConversionUtils.asPrivateKey("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"));
        System.out.println(stringWriter.toString());
    }
}
