package com.ahmadsaleh.bitcoinkeys

import spock.lang.Specification
import spock.lang.Unroll

/**
 * Created by Ahmad Y. Saleh on 7/20/17.
 */
class WalletImportFormatWriterTest extends Specification{

    @Unroll
    def "given a WalletImportFormatWriter, when writing a PrivateKey, then the correct wallet import format is generated"(){
        setup:
        def stringWriter = new StringWriter()
        def writer = new WalletImportFormatWriter(stringWriter)

        when:
        def privateKey = KeysConversionUtils.asPrivateKey(privateHex);
        writer.write(privateKey)
        writer.flush()

        then:
        wif.equals(stringWriter.toString())

        where:
        privateHex || wif
        "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D" || "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        "F921AE3BC318308B5052E3F114D8AC8FCB69A5B2D042016063E7F56B45ABF4E2" || "5Ki1K74XmQ2AZRT5nK8AjoY6tjedDYjfqykwpFBiyuNVswb6Xc8"
        "4FD5BBC123C20D82181C2CA67797CFDDFC62F9F3153F6B9AD2F624B66CB678A0" || "5JRSreU4aCPdDXitqMXd43ifLeP7PUTnjEt9FQ1uqHpAgKs7ExP"
        "E90811C0C3B05DAF38F21C260FB7F7E4C87A1921D730F13A34D20B0AB1A509EB" || "5Kav4NZJtPAfpLKX5qsykd6XpYJqSkp7UU51BkbYoG5M6SZtQPn"
        "12AF55F26BA54C4D7C51BBA2C2B492CD132EFEA9B915E24C701308E5CA57DACB" || "5HxWry9W99KL9MjVFKQcQHeSmVoowch4L76sq6hhNpWBKjMvcVP"
        "74BA2EB17F93DD41EBD80211627AB2ACC53AE9E66EB77C910DA1A01721188E92" || "5JhhDti3oXzHdAJQQrcSrJgVogGDKo6iCXUKECrZYQdmCFpjLx5"
        "45AA0C9DDA1BC527A9EDFA8DA995D23EA3FCEF88DAFBAF1742342546611BDFEB" || "5JLy4WpN8Y3DzVkrDhW3w3Qz6xnuthidZWgVAXMwy3gYHRT69im"
    }
}
