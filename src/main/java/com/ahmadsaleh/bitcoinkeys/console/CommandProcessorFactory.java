package com.ahmadsaleh.bitcoinkeys.console;

import com.ahmadsaleh.bitcoinkeys.console.processors.*;

import java.util.HashMap;
import java.util.Map;

public class CommandProcessorFactory {

    private static CommandProcessorFactory FACTORY = new CommandProcessorFactory();
    private static Map<String, CommandProcessor> processorMap = new HashMap<>();

    static {
        registerProcessor(new ExitCommandProcessor());
        registerProcessor(new GenerateCommandProcessor());
        registerProcessor(new EmptyCommandProcessor());
        registerProcessor(new DecryptCommandProcessor());
        registerProcessor(new CalculateAddressCommandProcessor());
    }

    private CommandProcessorFactory() {
    }

    private static void registerProcessor(CommandProcessor processor) {
        processorMap.put(processor.getCommand(), processor);
    }

    public static CommandProcessorFactory getFactory() {
        return FACTORY;
    }

    public CommandProcessor getProcessor(String command) {
        if(processorMap.get(command) == null){
            return new UnrecognizedCommadProcessor(command);
        }

        return processorMap.get(command);
    }
}
