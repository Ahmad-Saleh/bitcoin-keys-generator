package com.ahmadsaleh.bitcoinkeys

import spock.lang.Specification

/**
 * Created by Ahmad Y. Saleh on 7/20/17.
 */
class BitcoinAddressWriterTest extends Specification{

    def "given a BitcoinAddressWriter, when writing a PublicKey, then the correct address is generated"(){
        setup:
        def stringWriter = new StringWriter()
        def writer = new BitcoinAddressWriter(stringWriter)

        when:
        def publicKey = KeysConversionUtils.asPublicKey("0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6");
        writer.write(publicKey)
        writer.flush()

        then:
        "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM".equals(stringWriter.toString())
    }
}
