package com.ahmadsaleh.bitcoinkeys.console;

import java.util.List;

public interface CommandProcessor {

    void process(List<CommandOption> options);

    String getCommand();
}
