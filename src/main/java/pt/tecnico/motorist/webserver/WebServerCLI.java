package pt.tecnico.motorist.webserver;

import java.security.PublicKey;
import java.util.Scanner;

import pt.tecnico.motorist.KeyLoader;

public class WebServerCLI {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("WebServer CLI: Type 'help' for a list of commands or 'exit' to quit.");

        while (true) {
            System.out.print("WebServer> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Shutting down WebServer CLI...");
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

                    case "start-server":
                        if (commandArgs.length != 2) {
                            System.out.println("Usage: start-server <port>");
                            continue;
                        }
                        int port = Integer.parseInt(commandArgs[1]);
                        PublicKey senderPublicKey = KeyLoader.loadECPublicKey("src/main/resources/keys/owner_public_key_x509.pem");
                        webserver.startServer(port, senderPublicKey);
                        break;

                    case "retrieve-message":
                        if (commandArgs.length != 2) {
                            System.out.println("Usage: retrieve-message <firmwareID>");
                            continue;
                        }
                        String firmwareID = commandArgs[1];
                        String message = webserver.retrieveSecureMessage(firmwareID);
                        System.out.println("Retrieved message: " + message);
                        break;

                    case "db-status":
                        System.out.println("Database status: (To be implemented)");
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
        System.out.println("\nWebServer CLI Commands:");
        System.out.println("  help                     - Display this help message");
        System.out.println("  start-server <port>      - Start the WebServer on the specified port");
        System.out.println("  retrieve-message <ID>    - Retrieve a secure message by firmware ID");
        System.out.println("  db-status                - Check the status of the database");
        System.out.println("  exit                     - Exit the CLI");
    }
}
