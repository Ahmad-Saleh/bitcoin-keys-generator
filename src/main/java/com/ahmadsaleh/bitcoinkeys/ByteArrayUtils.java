package com.ahmadsaleh.bitcoinkeys;

import java.util.Arrays;

/**
 * Created by Ahmad Y. Saleh on 7/21/17.
 */
public final class ByteArrayUtils {

    private ByteArrayUtils() {
        throw new UnsupportedOperationException("utility class is not supposed to be used this way!");
    }

    public static byte[] addToStart(byte[] data, byte b) {
        byte[] result = new byte[data.length + 1];
        System.arraycopy(data, 0, result, 1, data.length);
        result[0] = b;
        return result;
    }

    public static byte[] copyOfRange(byte[] data, int from, int to){
        return Arrays.copyOfRange(data, from, to);
    }
}
