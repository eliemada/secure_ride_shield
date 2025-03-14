package pt.tecnico.motorist.mechanic;

import com.google.gson.JsonObject;
import pt.tecnico.motorist.KeyLoader;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class MechanicCLI {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Mechanic mechanic = new Mechanic("mechanic1");

        System.out.println("Mechanic CLI: Type 'help' for a list of commands or 'exit' to quit.");

        while (true) {
            System.out.print("Mechanic> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Shutting down Mechanic CLI...");
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

                    case "fetch-config":
                        if (commandArgs.length != 5) {
                            System.out.println("Usage: fetch-config <host> <port> <userId> <carId>");
                            continue;
                        }
                        String host = commandArgs[1];
                        int port = Integer.parseInt(commandArgs[2]);
                        String userId = commandArgs[3];
                        String carId = commandArgs[4];

                        // Load keys
                        PrivateKey userRsaPrivateKey = KeyLoader.loadRSAPrivateKey(
                                "src/main/resources/keys/owner_rsa_private_pkcs8.pem");
                        PublicKey carEcPublicKey = KeyLoader.loadECPublicKey(
                                "src/main/resources/keys/car_ec_public.pem");

                        // Fetch configuration
                        JsonObject config = mechanic.fetchConfiguration(host, port, userId, carId, carEcPublicKey, false);
                        if (config != null) {
                            System.out.println("Configuration fetched: " + config.toString());
                        } else {
                            System.out.println("No configuration available.");
                        }
                        break;

                    case "start-server":
                        if (commandArgs.length != 3) {
                            System.out.println("Usage: start-server <port> <host>");
                            continue;
                        }
                        int port1 = Integer.parseInt(commandArgs[1]);
                        String host1 = commandArgs[2];
                        PublicKey senderPublicKey = KeyLoader.loadECPublicKey("src/main/resources/keys/owner_public_key_x509.pem");
                        Mechanic.startServer(port1, host1,senderPublicKey);
                        break;

                    default:
                        System.out.println("Unknown command: " + command);
                        printHelp();
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        scanner.close();
    }

    private static void printHelp() {
        System.out.println("\nMechanic CLI Commands:");
        System.out.println("  help                         - Display this help message");
        System.out.println("  fetch-config <host> <port> <userId> <carId>");
        System.out.println("                               - Fetch car configuration");
        System.out.println("  start-server <port> <host>   - Start the server of the mechanic to get the user key");
        System.out.println("  exit                         - Exit the CLI");
    }
}
