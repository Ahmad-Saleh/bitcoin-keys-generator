package com.ahmadsaleh.bitcoinkeys.conversion.converter;

public interface TypeConverter<F, T> {

    T convert(Object subject);

    Class<F> getFromType();

    Class<T> getToType();
}
