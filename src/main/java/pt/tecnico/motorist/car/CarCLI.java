package pt.tecnico.motorist.car;

import java.util.Scanner;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.DatabaseMetaData;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import pt.tecnico.motorist.KeyLoader;

/**
 * Command Line Interface for the Car system that provides interactive management
 * of vehicle configurations and server operations. This CLI allows users to:
 * - Start/stop the car server
 * - Manage vehicle configurations
 * - Monitor and control database operations
 * - View system status
 * 
 * The CLI integrates with a SQLite database for persistent storage and uses
 * public/private key pairs for secure operations.
 */
public class CarCLI {
    private static final String DB_URL = "jdbc:sqlite:src/main/resources/db/car_config.db";
    private static Car currentCar;
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    /**
     * Main entry point for the Car CLI application. Initializes the car instance
     * with security keys and starts the interactive command loop.
     *
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Car CLI: Type 'help' for a list of commands or 'exit' to quit.");

        // Initialize car with required security keys
        try {
            PrivateKey carRsaPrivateKey = KeyLoader.loadRSAPrivateKey(
                    "src/main/resources/keys/car_rsa_private_pkcs8.pem");
            PublicKey carRsaPublicKey = KeyLoader.loadRSAPublicKey(
                    "src/main/resources/keys/car_rsa_public.pem");
            PrivateKey carEcPrivateKey = KeyLoader.loadECPrivateKey(
                    "src/main/resources/keys/car_ec_private_pkcs8.pem");

            currentCar = new Car(carRsaPrivateKey, carRsaPublicKey, carEcPrivateKey);
        } catch (Exception e) {
            System.err.println("Failed to initialize car: " + e.getMessage());
            System.exit(1);
        }

        // Main command processing loop
        while (true) {
            System.out.print("Car> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Shutting down Car CLI...");
                break;
            }

            String[] commandArgs = input.split("\\s+");
            if (commandArgs.length < 1) {
                printHelp();
                continue;
            }

            String command = commandArgs[0];

            try {
                processCommand(command.toLowerCase(), commandArgs);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        scanner.close();
    }

    /**
     * Retrieves and displays the current status of the database, including connection
     * details and configuration statistics.
     *
     * @throws Exception If database access fails
     */
    private static void printDatabaseStatus() throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            DatabaseMetaData metaData = conn.getMetaData();
            System.out.println("\nDatabase Status:");
            System.out.println("  Connection URL: " + DB_URL);
            System.out.println("  Driver: " + metaData.getDriverName() + " " + metaData.getDriverVersion());

            // Query for database statistics
            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT COUNT(*) as total, COUNT(DISTINCT carID) as cars FROM secure_messages");
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                System.out.println("  Total configurations: " + rs.getInt("total"));
                System.out.println("  Unique cars: " + rs.getInt("cars"));
            }
        }
    }

    /**
     * Lists all configurations stored in the database for a specific car.
     *
     * @param carId The unique identifier of the car
     * @throws Exception If database access fails
     */
    private static void listConfigurations(String carId) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT timestamp, message FROM secure_messages WHERE carID = ? ORDER BY timestamp DESC");
            stmt.setString(1, carId);

            ResultSet rs = stmt.executeQuery();
            System.out.println("\nConfigurations for car " + carId + ":");
            int count = 0;
            while (rs.next()) {
                count++;
                System.out.println("  " + count + ". Timestamp: " + rs.getString("timestamp"));
            }
            if (count == 0) {
                System.out.println("No configurations found.");
            }
        }
    }

    /**
     * Displays the most recent configuration for a specific car.
     *
     * @param carId The unique identifier of the car
     * @throws Exception If database access fails or configuration parsing fails
     */
    private static void showLatestConfiguration(String carId) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT message FROM secure_messages WHERE carID = ? ORDER BY timestamp DESC LIMIT 1");
            stmt.setString(1, carId);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String message = rs.getString("message");
                JsonObject config = gson.fromJson(message, JsonObject.class);
                System.out.println("\nLatest configuration for car " + carId + ":");
                System.out.println(gson.toJson(config));
            } else {
                System.out.println("No configuration found for car " + carId);
            }
        }
    }

    /**
     * Removes all stored configurations for a specific car.
     *
     * @param carId The unique identifier of the car
     * @throws Exception If database access fails
     */
    private static void clearConfigurations(String carId) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            PreparedStatement stmt = conn.prepareStatement(
                    "DELETE FROM secure_messages WHERE carID = ?");
            stmt.setString(1, carId);

            int deleted = stmt.executeUpdate();
            System.out.println("Deleted " + deleted + " configurations for car " + carId);
        }
    }

    /**
     * Processes a command with its arguments and executes the appropriate action.
     *
     * @param command The command to execute
     * @param args Array of command arguments
     * @throws Exception If command execution fails
     */
    private static void processCommand(String command, String[] args) throws Exception {
        switch (command) {
            case "help":
                printHelp();
                break;

            case "start-server":
                if (args.length != 2) {
                    System.out.println("Usage: start-server <port>");
                    return;
                }
                int port = Integer.parseInt(args[1]);
                System.out.println("Starting car server on port " + port + "...");
                currentCar.startServer(port);
                break;

            case "db-status":
                printDatabaseStatus();
                break;

            case "toggle-db":
                if (args.length != 2) {
                    System.out.println("Usage: toggle-db <true|false>");
                    return;
                }
                boolean enableDb = Boolean.parseBoolean(args[1]);
                currentCar.setSaveToDb(enableDb);
                System.out.println("Database storage " + (enableDb ? "enabled" : "disabled"));
                break;

            case "list-configs":
                if (args.length != 2) {
                    System.out.println("Usage: list-configs <carID>");
                    return;
                }
                listConfigurations(args[1]);
                break;

            case "show-config":
                if (args.length != 2) {
                    System.out.println("Usage: show-config <carID>");
                    return;
                }
                showLatestConfiguration(args[1]);
                break;

            case "clear-db":
                if (args.length != 2) {
                    System.out.println("Usage: clear-db <carID>");
                    return;
                }
                clearConfigurations(args[1]);
                break;

            default:
                System.out.println("Unknown command: " + command);
                printHelp();
                break;
        }
    }

    /**
     * Displays the help message showing all available commands and their usage.
     */
    private static void printHelp() {
        System.out.println("\nCar CLI Commands:");
        System.out.println("  help                  - Display this help message");
        System.out.println("  start-server <port>   - Start the Car server on the specified port");
        System.out.println("  db-status            - Check the status of the database");
        System.out.println("  toggle-db <true|false> - Enable/disable database storage");
        System.out.println("  list-configs <carID>  - List all configurations for a car");
        System.out.println("  show-config <carID>   - Show the latest configuration for a car");
        System.out.println("  clear-db <carID>      - Clear all configurations for a car");
        System.out.println("  exit                  - Exit the CLI");
    }
}