package com.ahmadsaleh.bitcoinkeys.console.processors;

import com.ahmadsaleh.bitcoinkeys.console.CommandOption;
import com.ahmadsaleh.bitcoinkeys.console.CommandProcessor;

import java.util.List;

public class EmptyCommandProcessor implements CommandProcessor {
    @Override
    public void process(List<CommandOption> options) {
    }

    @Override
    public String getCommand() {
        return "";
    }
}
