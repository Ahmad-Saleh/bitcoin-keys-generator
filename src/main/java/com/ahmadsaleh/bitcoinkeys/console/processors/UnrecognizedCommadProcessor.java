package com.ahmadsaleh.bitcoinkeys.console.processors;

import com.ahmadsaleh.bitcoinkeys.console.CommandOption;
import com.ahmadsaleh.bitcoinkeys.console.CommandProcessor;

import java.util.List;

public class UnrecognizedCommadProcessor implements CommandProcessor {

    private String command;

    public UnrecognizedCommadProcessor(String command) {
        this.command = command;
    }

    @Override
    public void process(List<CommandOption> options) {
        System.out.printf("command '%s' is not recognized!\n", command);
    }

    @Override
    public String getCommand() {
        throw new UnsupportedOperationException("This should not be called! This is a Null Object Pattern " +
                "and there is no specific command is attached to this processor");
    }
}
