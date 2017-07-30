package com.ahmadsaleh.bitcoinkeys.console;

import com.ahmadsaleh.bitcoinkeys.console.processors.ExitCommandProcessor;
import com.ahmadsaleh.bitcoinkeys.console.processors.GenerateCommandProcessor;
import com.ahmadsaleh.bitcoinkeys.console.processors.UnrecognizedCommadProcessor;

import java.util.HashMap;
import java.util.Map;

public class CommandProcessorFactory {

    private static CommandProcessorFactory FACTORY = new CommandProcessorFactory();
    private static Map<String, CommandProcessor> processorMap = new HashMap<>();

    static {
        registerProcessor(new ExitCommandProcessor());
        registerProcessor(new GenerateCommandProcessor());
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
