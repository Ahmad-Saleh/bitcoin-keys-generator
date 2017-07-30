package com.ahmadsaleh.bitcoinkeys.console.processors;

import com.ahmadsaleh.bitcoinkeys.console.CommandOption;
import com.ahmadsaleh.bitcoinkeys.console.CommandProcessor;
import com.ahmadsaleh.bitcoinkeys.console.ConsoleUtils;
import net.bither.bitherj.crypto.bip38.Bip38;
import net.bither.bitherj.exception.AddressFormatException;

import java.util.List;

public class DecryptCommandProcessor implements CommandProcessor {
    @Override
    public void process(List<CommandOption> options) {
        if(options.size() != 1){
            System.err.printf("Invalid command, expected one option '-key'\n");
            return;
        }
        CommandOption keyOption = options.get(0);
        if(!keyOption.getOption().equals("key")){
            System.err.printf("Invalid option. expected '-key' but found '-%s'\n", keyOption.getOption());
            return;
        }

        try {
            CharSequence password = ConsoleUtils.requestPassword();
            CharSequence decrypt = Bip38.decrypt(keyOption.getArguments(), password);
            if(decrypt == null){
                System.err.println("failed to decrypt key");
            }else {
                System.out.printf("private key: %s", decrypt);
            }
        } catch (InterruptedException | AddressFormatException e) {
            throw new IllegalStateException("Error while decrypting key", e);
        }
    }

    @Override
    public String getCommand() {
        return "decrypt";
    }
}
