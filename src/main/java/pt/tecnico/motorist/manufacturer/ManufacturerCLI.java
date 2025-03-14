package pt.tecnico.motorist.manufacturer;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import pt.tecnico.motorist.KeyLoader;

/**
 * Command Line Interface for the Manufacturer system that allows interaction
 * with connected vehicles.
 * This CLI provides functionality for sending firmware updates to cars and
 * managing manufacturer
 * operations through a text-based interface.
 * 
 * The CLI supports commands for:
 * - Sending firmware updates to cars
 * - Displaying help information
 * - Graceful system shutdown
 */
public class ManufacturerCLI {

    /**
     * Main entry point for the Manufacturer CLI application.
     * Initializes the manufacturer instance and starts an interactive command loop
     * that processes user commands until exit is requested.
     *
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Manufacturer manufacturer = new Manufacturer("manufacturer");

        System.out.println("Manufacturer CLI: Type 'help' for a list of commands or 'exit' to quit.");

        while (true) {
            System.out.print("Manufacturer> ");
            String input = scanner.nextLine().trim();

            // Check for exit command
            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Shutting down Manufacturer CLI...");
                break;
            }

            // Parse command arguments
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

                    case "send-firmware":
                        // Validate command arguments
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: send-firmware <firmwareID> <host> <port>");
                            continue;
                        }

                        String firmwareID = commandArgs[1];
                        String host = commandArgs[2];
                        int port;

                        // Parse and validate port number
                        try {
                            port = Integer.parseInt(commandArgs[3]);
                        } catch (NumberFormatException e) {
                            System.out.println("Error: Port must be a valid number");
                            continue;
                        }

                        // Process firmware update
                        System.out.println("Retrieving firmware update...");
                        String firmwareUpdate = manufacturer.retrieveFirmwareUpdate(firmwareID);

                        // Load required security keys
                        System.out.println("Loading keys...");
                        PrivateKey manufacturerPrivateKey = KeyLoader.loadECPrivateKey(
                                "src/main/resources/keys/manufacturer_ec_private_pkcs8.pem");
                        PublicKey carPublicKey = KeyLoader.loadRSAPublicKey(
                                "src/main/resources/keys/car_rsa_public.pem");

                        // Send firmware update to car
                        System.out.println("Sending firmware update to car through " + host + ":" + port);
                        manufacturer.sendFirmwareToCar(firmwareUpdate, manufacturerPrivateKey, carPublicKey, host,
                                port);
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

    /**
     * Displays the help message showing available commands and their usage.
     * Includes examples to help users understand the command syntax.
     */
    private static void printHelp() {
        System.out.println("\nManufacturer CLI Commands:");
        System.out.println(" help - Display this help message");
        System.out.println(" send-firmware <ID> <host> <port> - Send a firmware update to the car");
        System.out.println(" exit - Exit the CLI");
        System.out.println("\nExample:");
        System.out.println(" send-firmware 1234 localhost 5000 - Send firmware update through localhost:5000");
    }
}