package pt.tecnico.motorist;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

import java.util.Scanner;

public class CLI {

    public static void main(String[] args) {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to the MotorIST CLI tool!");
        System.out.println("Type 'help' for a list of available commands or 'exit' to quit.");

        while (true) {
            System.out.print("> "); // Prompt
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Exiting... Goodbye!");
                break;
            }

            String[] commandArgs = input.split("\\s+");
            if (commandArgs.length < 1) {
                printHelp();
                continue;
            }

            String command = commandArgs[0];
            try {
                switch (command.toLowerCase()) {
                    case "help":
                        printHelp();
                        break;

                    case "protect":
                        if (commandArgs.length != 5) {
                            System.out.println("Usage: protect <input-file> <output-file> <sender-private-key> <receiver-public-key>");
                            continue;
                        }
                        Protect.protect(
                            commandArgs[1],
                            commandArgs[2],
                            KeyLoader.loadECPrivateKey(commandArgs[3]),
                            KeyLoader.loadRSAPublicKey(commandArgs[4])
                        );
                        break;

                    case "check":
                        if (commandArgs.length != 2) {
                            System.out.println("Usage: check <input-file>");
                            continue;
                        }
                        boolean result = Check.check(commandArgs[1], KeyLoader.loadECPublicKey(commandArgs[1]));
                        System.out.println("Verification result: " + (result ? "Valid" : "Invalid"));
                        break;

                    case "unprotect":
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: unprotect <input-file> <dummy-key> <output-file>");
                            continue;
                        }
                        Unprotect.unprotect(
                            commandArgs[1],
                            commandArgs[3],
                            KeyLoader.loadRSAPrivateKey(commandArgs[2])
                        );
                        break;

                    default:
                        System.out.println("Unknown command: " + command);
                        printHelp();
                        break;
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        scanner.close();
    }

    private static void printHelp() {
        System.out.println("\nAvailable Commands:");
        System.out.println("  help                       - Display this help message");
        System.out.println("  protect <input-file> <output-file> <sender-private-key> <receiver-public-key> - Protect a file");
        System.out.println("  check <input-file>         - Check a file for integrity");
        System.out.println("  unprotect <input-file> <dummy-key> <output-file> - Unprotect a file");
        System.out.println("  exit                       - Exit the CLI");
    }
}
