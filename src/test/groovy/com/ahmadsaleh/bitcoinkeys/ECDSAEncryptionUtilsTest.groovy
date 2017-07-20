package com.ahmadsaleh.bitcoinkeys

import spock.lang.Specification

/**
 *  Created by Ahmad Y. Saleh on 17/07/17.
 */
class ECDSAEncryptionUtilsTest extends Specification {

    def "given ECDSAEncryptionUtils, when generating key pair, then non-null is returned"() {
        when:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()

        then:
        keyPair != null
    }

    def "given ECDSAEncryptionUtils, when generating key pair, then non-null private and public keys can be retrieved"() {
        when:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()

        then:
        keyPair.private != null
        keyPair.public != null
    }

    def "given ECDSA key pair, when signing null text, then an IllegalArgumentException is thrown"() {
        setup:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()

        when:
        ECDSAEncryptionUtils.sign(null, keyPair.private)

        then:
        thrown IllegalArgumentException
    }

    def "given ECDSAEncryptionUtils, when signing with null private key, then an IllegalArgumentException is thrown"() {
        when:
        ECDSAEncryptionUtils.sign("sample", null)

        then:
        thrown IllegalArgumentException
    }

    def "given ECDSA key pair and a text signature, when verifying the signature of null text, then an IllegalArgumentException is thrown"() {
        setup:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()
        def signature = ECDSAEncryptionUtils.sign("sample", keyPair.private)

        when:
        ECDSAEncryptionUtils.verify(null, signature, keyPair.public)

        then:
        thrown IllegalArgumentException
    }

    def "given ECDSA key pair, when verifying null signature, then an IllegalArgumentException is thrown"() {
        setup:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()

        when:
        ECDSAEncryptionUtils.verify("sample", null, keyPair.public)

        then:
        thrown IllegalArgumentException
    }

    def "given ECDSA key pair and a text signature, when verifying with null public key, then an IllegalArgumentException is thrown"() {
        setup:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()
        def signature = ECDSAEncryptionUtils.sign("sample", keyPair.private)

        when:
        ECDSAEncryptionUtils.verify("sample", signature, null)

        then:
        thrown IllegalArgumentException
    }

    def "given ECDSA key pair and a text signature, when verifying the signature of different text, then verification will fail"() {
        setup:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()
        def signature = ECDSAEncryptionUtils.sign("sample", keyPair.private)

        when:
        def result = ECDSAEncryptionUtils.verify("other text", signature, keyPair.public)

        then:
        !result
    }

    def "given 2 ECDSA key pairs and a text signature with first pair's private, when verifying the signature of the text with the second public, then verification will fail"() {
        setup:
        def firstKeyPair = ECDSAEncryptionUtils.generateKeyPair()
        def secondKeyPair = ECDSAEncryptionUtils.generateKeyPair()
        def signature = ECDSAEncryptionUtils.sign("sample", firstKeyPair.private)

        when:
        def result = ECDSAEncryptionUtils.verify("sample", signature, secondKeyPair.public)

        then:
        !result
    }

    def "given ECDSA key pair and a text signature, when verifying the signature of the text, then verification will succeed"() {
        setup:
        def keyPair = ECDSAEncryptionUtils.generateKeyPair()
        def signature = ECDSAEncryptionUtils.sign("sample", keyPair.private)

        when:
        def result = ECDSAEncryptionUtils.verify("sample", signature, keyPair.public)

        then:
        result
    }
}
