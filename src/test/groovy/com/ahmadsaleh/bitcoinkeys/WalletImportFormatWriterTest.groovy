package com.ahmadsaleh.bitcoinkeys

import spock.lang.Specification

/**
 * Created by Ahmad Y. Saleh on 7/20/17.
 */
class WalletImportFormatWriterTest extends Specification{

    def "given a WalletImportFormatWriter, when writing a PrivateKey, then the correct wallet import format is generated"(){
        setup:
        def stringWriter = new StringWriter()
        def writer = new WalletImportFormatWriter(stringWriter)

        when:
        def privateKey = KeysConversionUtils.asPrivateKey("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D");
        writer.write(privateKey)
        writer.flush()

        then:
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ".equals(stringWriter.toString())
    }
}
