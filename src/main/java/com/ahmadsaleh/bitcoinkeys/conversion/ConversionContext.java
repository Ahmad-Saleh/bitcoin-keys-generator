package com.ahmadsaleh.bitcoinkeys.conversion;

import com.ahmadsaleh.bitcoinkeys.ECDSAEncryptionUtils;
import com.ahmadsaleh.bitcoinkeys.conversion.converter.*;

import java.util.*;

public class ConversionContext {

    private static Map<Class, List<TypeConverter>> converterMap = new HashMap<>();
    private Object subject;

    static {
        registerConverter(new BitcoinAddressToByteArrayConverter());
        registerConverter(new ByteArrayToPrivateKeyConverter());
        registerConverter(new ByteArrayToPublicKeyConverter());
        registerConverter(new PrivateKeyToByteArrayConverter());
        registerConverter(new PrivateKeyToWifConverter());
        registerConverter(new PublicKeyToBitcoinAddressConverter());
        registerConverter(new PublicKeyToByteArrayConverter());
        registerConverter(new WifToPrivateKeyConverter());
    }

    private static <F, T> void registerConverter(TypeConverter<F, T> typeConverter) {
        if (converterMap.get(typeConverter.getFromType()) == null) {
            converterMap.put(typeConverter.getFromType(), new ArrayList<>());
        }
        converterMap.get(typeConverter.getFromType()).add(typeConverter);
    }

    public ConversionContext(Object subject) {
        this.subject = subject;
    }

    public <T> T convertTo(Class<T> type) {
        return (T) findConverter(subject.getClass(), type).convert(subject);
    }

    private <F, T> TypeConverter findConverter(Class<F> fromType, Class<T> toType) {
        return converterMap.entrySet().stream().filter(entry -> entry.getKey().isAssignableFrom(fromType))
                .map(entry -> entry.getValue().stream()).reduce((first, second) -> first.)
                .orElseThrow(() -> new ConversionException("cannot find a converter from " + fromType.getName() + " to " + toType.getName()))
                .get(0);
    }

    private <T> List<T> mergeLists(List<T> first, List<T> second) {
        List<T> result = new ArrayList<>();
        result.addAll(first);
        result.addAll(second);
        return result;
    }

    public static void main(String[] args) {
        ConversionContext conversionContext = new ConversionContext(ECDSAEncryptionUtils.generateKeyPair().getPrivate());
        System.out.println(conversionContext.convertTo(Byte.class));
    }
}
