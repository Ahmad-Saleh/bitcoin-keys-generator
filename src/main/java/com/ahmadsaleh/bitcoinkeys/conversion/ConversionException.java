package com.ahmadsaleh.bitcoinkeys.conversion;

public class ConversionException extends RuntimeException {

    public ConversionException(String message) {
        super(message);
    }

    public ConversionException(String message, Throwable t) {
        super(message, t);
    }
}
