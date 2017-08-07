package com.ahmadsaleh.bitcoinkeys.console.processors;

import com.ahmadsaleh.bitcoinkeys.ECDSAEncryptionUtils;
import com.ahmadsaleh.bitcoinkeys.KeysConversionUtils;
import com.ahmadsaleh.bitcoinkeys.console.CommandOption;
import com.ahmadsaleh.bitcoinkeys.console.CommandProcessor;
import com.ahmadsaleh.bitcoinkeys.console.ConsoleUtils;
import com.ahmadsaleh.bitcoinkeys.writer.WalletImportFormatWriter;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.bip38.Bip38;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public class CalculateAddressCommandProcessor implements CommandProcessor {

    @Override
    public void process(List<CommandOption> options) {
        if (options.size() != 1) {
            System.err.printf("Invalid command, expected one option '-private'\n");
            return;
        }
        CommandOption keyOption = options.get(0);
        if (!keyOption.getOption().equals("private")) {
            System.err.printf("Invalid option. expected '-private' but found '-%s'\n", keyOption.getOption());
            return;
        }

        try {
            CharSequence password = ConsoleUtils.requestPassword();
            CharSequence decrypt = Bip38.decrypt(keyOption.getArguments(), password);
            if (decrypt == null) {
                System.err.println("failed to decrypt key");
            } else {
                String walletImportFormat = decrypt.toString();
                String address = calculateAddress(walletImportFormat);
                System.out.printf("address: %s\n", address);
            }
        } catch (InterruptedException | AddressFormatException e) {
            throw new IllegalStateException("Error while decrypting key", e);
        }
    }

    private String calculateAddress(String walletImportFormat) {
        PrivateKey privateKey = KeysConversionUtils.toPrivateKey(walletImportFormat);
        byte[] publicKeyBytes = ECKey.publicKeyFromPrivate(new BigInteger(1, KeysConversionUtils.asByteArray(privateKey)), false);
        PublicKey publicKey = KeysConversionUtils.asPublicKey(publicKeyBytes);
        return KeysConversionUtils.toBitcoinAddress(publicKey);
    }

    @Override
    public String getCommand() {
        return "calculate";
    }

}
