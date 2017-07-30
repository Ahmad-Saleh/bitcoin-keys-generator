package com.ahmadsaleh.bitcoinkeys.console;

import net.bither.bitherj.crypto.SecureCharSequence;

import java.util.Arrays;

public class ConsoleUtils {

    public static CharSequence requestNewPassword() {
        char[] password;
        char[] passwordConfirm;
        do {
            password = System.console().readPassword("Enter password: ");
            passwordConfirm = System.console().readPassword("Confirm password: ");
            if (!Arrays.equals(password, passwordConfirm)) {
                System.err.println("Password and confirmation do not match!");
            }
        } while (!Arrays.equals(password, passwordConfirm));
        return new SecureCharSequence(password);
    }

    public static CharSequence requestPassword() {
        return new SecureCharSequence(System.console().readPassword("Enter password: "));
    }
}
