package pt.tecnico.motorist.client;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import com.google.gson.JsonObject;
import com.google.gson.GsonBuilder;
import com.google.gson.Gson;
import pt.tecnico.motorist.AuditCrypto;
import pt.tecnico.motorist.Check;
import pt.tecnico.motorist.KeyLoader;
import pt.tecnico.motorist.Protect;
import pt.tecnico.motorist.Unprotect;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * UserCLI provides a command-line interface for users to interact with the car management system.
 * It supports various operations including connecting to car servers, managing configurations,
 * handling encryption/decryption of files, and auditing system activities.
 * 
 * The CLI supports two types of users (user1 and user2) with different key pairs for authentication
 * and secure communication with the car system.
 */
public class UserCLI {
    /** The currently authenticated user instance */
    private static User currentUser;
    
    /** Gson instance for JSON processing with pretty printing enabled */
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    /**
     * Main entry point for the User CLI application.
     * Initializes the user interface and processes user commands in a continuous loop
     * until the exit command is received.
     *
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("User CLI: Type 'help' for a list of commands or 'exit' to quit.");

        // Initialize user with ID input
        System.out.print("Enter user ID: ");
        String userId = scanner.nextLine().trim();
        currentUser = new User(userId);
        System.out.println("User initialized with ID: " + userId);

        while (true) {
            System.out.print("User> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Shutting down User CLI...");
                break;
            }

            // Split input into command and arguments
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
                        // Validate command arguments and encrypt file
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: protect <input-file> <dummy-key> <output-file>");
                            continue;
                        }
                        Protect.protect(commandArgs[1], commandArgs[3],
                                KeyLoader.loadRSAPrivateKey(commandArgs[2]),
                                KeyLoader.loadRSAPublicKey(commandArgs[2]));
                        break;

                    case "check":
                        // Validate and verify file integrity
                        if (commandArgs.length != 2) {
                            System.out.println("Usage: check <input-file>");
                            continue;
                        }
                        boolean result = Check.check(commandArgs[1],
                                KeyLoader.loadECPublicKey(commandArgs[1]));
                        System.out.println("Verification result: " + (result ? "Valid" : "Invalid"));
                        break;

                    case "public-info":
                        // Fetch and display public car information
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: public-info <carID> <host> <port>");
                            continue;
                        }
                        try {
                            String targetCarId = commandArgs[1];
                            String hostName = commandArgs[2];
                            int port = Integer.parseInt(commandArgs[3]);
                            JsonObject publicInfo = currentUser.fetchPublicInfo(hostName, port, targetCarId);

                            if (publicInfo != null && publicInfo.has("public_car_info")) {
                                System.out.println("Public car information:");
                                System.out.println(gson.toJson(publicInfo.get("public_car_info")));
                            } else {
                                System.out.println("No public information available");
                            }
                        } catch (Exception e) {
                            System.err.println("Error fetching public info: " + e.getMessage());
                        }
                        break;

                    case "connect":
                        // Process connection request with proper key file selection
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: connect <host> <port> <file>");
                            continue;
                        }
                        String host = commandArgs[1];
                        int port = Integer.parseInt(commandArgs[2]);
                        String path = "src/main/resources/";
                        String configFileName = commandArgs[3];

                        // Select appropriate key file based on user ID
                        String userKeyFileName;
                        if (currentUser.getUserId().equals("user1")) {
                            userKeyFileName = "owner_ec_private_pkcs8.pem";
                        } else if (currentUser.getUserId().equals("user2")) {
                            userKeyFileName = "owner2_ec_private_pkcs8.pem";
                        } else {
                            System.out.println("Invalid user ID: " + currentUser.getUserId());
                            break;
                        }

                        String userKeyPath = "src/main/resources/keys/" + userKeyFileName;

                        // Load necessary keys for secure communication
                        PrivateKey senderEcPrivateKey = KeyLoader.loadECPrivateKey(userKeyPath);
                        PublicKey receiverRsaPublicKey = KeyLoader.loadRSAPublicKey(
                                "src/main/resources/keys/car_rsa_public.pem");

                        currentUser.sendSecureMessage(host, port,
                                path + configFileName,
                                senderEcPrivateKey, receiverRsaPublicKey);
                        break;

                    case "fetch":
                        // Fetch and display car configuration
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: fetch <carID> <host> <port>");
                            continue;
                        }
                        String carId = commandArgs[1];
                        String hostName = commandArgs[2];
                        int fetchPort = Integer.parseInt(commandArgs[3]);

                        // Select appropriate RSA key based on user ID
                        String userRsaKeyFileName;
                        if (currentUser.getUserId().equals("user1")) {
                            userRsaKeyFileName = "owner_rsa_private_pkcs8.pem";
                        } else if (currentUser.getUserId().equals("user2")) {
                            userRsaKeyFileName = "owner2_rsa_private_pkcs8.pem";
                        } else {
                            System.out.println("Invalid user ID: " + currentUser.getUserId());
                            break;
                        }

                        try {
                            userKeyPath = "src/main/resources/keys/" + userRsaKeyFileName;
                            PrivateKey userRsaPrivateKey = KeyLoader.loadRSAPrivateKey(userKeyPath);
                            PublicKey carEcPublicKey = KeyLoader.loadECPublicKey(
                                    "src/main/resources/keys/car_ec_public.pem");

                            JsonObject config = currentUser.fetchConfiguration(hostName, fetchPort, carId,
                                    userRsaPrivateKey,
                                    carEcPublicKey);
                            if (config != null) {
                                System.out.println("Fetched configuration:");
                                System.out.println(gson.toJson(config));
                            }
                        } catch (Exception e) {
                            System.err.println("Error fetching configuration: " + e.getMessage());
                        }
                        break;

                    case "get":
                        // Retrieve specific configuration value
                        if (commandArgs.length != 3) {
                            System.out.println("Usage: get <category> <key>");
                            continue;
                        }
                        String category = commandArgs[1];
                        String key = commandArgs[2];
                        String value = currentUser.getConfigValue(category, key);
                        if (value != null) {
                            System.out.println(category + " " + key + ": " + value);
                        } else {
                            System.out.println("Configuration value not found for " +
                                    category + " " + key);
                        }
                        break;

                    case "unprotect":
                        // Decrypt protected file
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: unprotect <input-file> <dummy-key> <output-file>");
                            continue;
                        }
                        Unprotect.unprotect(commandArgs[1], commandArgs[3],
                                KeyLoader.loadRSAPrivateKey(commandArgs[2]));
                        break;

                    case "audit":
                        // Process audit request and verify response integrity
                        if (commandArgs.length != 4) {
                            System.out.println("Usage: audit <carID> <host> <port>");
                            continue;
                        }
                        try {
                            String targetCarId = commandArgs[1];
                            String auditHost = commandArgs[2];
                            int auditPort = Integer.parseInt(commandArgs[3]);
                            
                            // Load appropriate keys based on user ID
                            PrivateKey userRsaPrivateKey;
                            PublicKey carEcPublicKey;

                            if (currentUser.getUserId().equals("user1")) {
                                userRsaPrivateKey = KeyLoader.loadRSAPrivateKey(
                                        "src/main/resources/keys/owner_rsa_private_pkcs8.pem");
                            } else if (currentUser.getUserId().equals("user2")) {
                                userRsaPrivateKey = KeyLoader.loadRSAPrivateKey(
                                        "src/main/resources/keys/owner2_rsa_private_pkcs8.pem");
                            } else {
                                System.out.println("Invalid user ID: " + currentUser.getUserId());
                                break;
                            }

                            carEcPublicKey = KeyLoader.loadECPublicKey(
                                    "src/main/resources/keys/car_ec_public.pem");

                            // Establish secure connection and send audit request
                            try (SSLSocket socket = User.createSSLSocket(auditHost, auditPort)) {
                                socket.startHandshake();

                                // Format and send audit request
                                String auditRequest = "AUDIT:" + targetCarId + ":" + currentUser.getUserId();
                                OutputStream os = socket.getOutputStream();
                                os.write(auditRequest.getBytes());
                                os.flush();

                                // Receive and process encrypted response
                                InputStream is = socket.getInputStream();
                                byte[] data = new byte[16384]; // Buffer size for encrypted data
                                int len = is.read(data);

                                if (len <= 0) {
                                    System.out.println("No audit data received");
                                    continue;
                                }

                                String protectedResponse = new String(data, 0, len);

                                if (protectedResponse.startsWith("ERROR:")) {
                                    System.out.println("Error: " + protectedResponse.substring(6));
                                    continue;
                                }

                                // Verify response signature
                                boolean isValid = AuditCrypto.check(protectedResponse, carEcPublicKey);
                                System.out.println("Signature verification result: " + isValid);

                                if (!isValid) {
                                    System.out.println("Warning: Audit trail signature verification failed!");
                                    continue;
                                }

                                // Decrypt and process audit trail
                                String decryptedAudit = AuditCrypto.unprotect(protectedResponse, userRsaPrivateKey);
                                System.out.println("Decrypted audit size (bytes): " + decryptedAudit.getBytes().length);
                                System.out.println("First 100 chars of decrypted audit: " +
                                        decryptedAudit.substring(0, Math.min(100, decryptedAudit.length())));

                                // Parse and verify audit trail integrity
                                JsonObject auditData = gson.fromJson(decryptedAudit, JsonObject.class);

                                boolean integrityValid = AuditCrypto.verifyAuditTrailIntegrity(
                                        decryptedAudit,
                                        targetCarId,
                                        protectedResponse,
                                        carEcPublicKey);
                                System.out.println("Integrity verification result: " + integrityValid);

                                if (!integrityValid) {
                                    System.out.println("Warning: Audit trail integrity check failed!");
                                    JsonObject metadata = auditData.getAsJsonObject("audit_metadata");
                                    if (metadata != null) {
                                        System.out.println(
                                                "Audit metadata car_id: " + metadata.get("car_id").getAsString());
                                        System.out.println("Expected car_id: " + targetCarId);
                                    }
                                    continue;
                                }

                                System.out.println("\nAudit trail for car " + targetCarId + ":");
                                System.out.println(gson.toJson(auditData));
                            }
                        } catch (Exception e) {
                            System.err.println("Error performing audit: " + e.getMessage());
                            e.printStackTrace();
                        }
                        break;
                    case "give-key" :
                        if (commandArgs.length != 3) {
                            System.out.println("Usage: give-key <host> <port>");
                            continue;
                        }
                        
                        int port1 = Integer.parseInt(commandArgs[2]);

                        String userKeyFileNameEC = "";
                        String userKeyFileNameRSA = "";
                        if (currentUser.getUserId().equals("user1")) {
                            userKeyFileNameEC = "owner_ec_private_pkcs8.pem";
                            userKeyFileNameRSA = "owner_rsa_private_pkcs8.pem";
                        } else if (currentUser.getUserId().equals("user2")) {
                            userKeyFileNameEC = "owner2_ec_private_pkcs8.pem";
                            userKeyFileNameRSA = "owner2_rsa_private_pkcs8.pem";
                        } else {
                            System.out.println("Invalid user ID: " + currentUser.getUserId());
                            break;
                        }

                        String userKeyPathEC = "src/main/resources/keys/" + userKeyFileNameEC;
                        String userKeyPathRSA = "src/main/resources/keys/" + userKeyFileNameRSA;

                        // Load necessary keys for secure communication
                        PrivateKey senderEcPrivateKey1 = KeyLoader.loadECPrivateKey(userKeyPathEC);
                        PublicKey receiverRsaPublicKey1 = KeyLoader.loadRSAPublicKey(
                                "src/main/resources/keys/mechanic_rsa_public.pem");

                        
            
                        User.giveKey(commandArgs[1], port1,userKeyPathRSA, senderEcPrivateKey1, receiverRsaPublicKey1);
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
     * Displays help information about available commands and their usage.
     * Includes command syntax, descriptions, and example usage for all supported operations.
     */
    /**
 * Displays help information about available commands and their usage.
 * Includes command syntax, descriptions, and example usage for all supported operations.
 */
private static void printHelp() {
    System.out.println("\nUser CLI Commands:");
    System.out.println("  help");
    System.out.println("    Display this help message");
    
    System.out.println("  connect <host> <port> <file>");
    System.out.println("    Connect to car server and send configuration from specified file");
    
    System.out.println("  fetch <carID> <host> <port>");
    System.out.println("    Fetch encrypted configuration for specified car");
    
    System.out.println("  get <category> <key>");
    System.out.println("    Retrieve specific configuration value from loaded configuration");
    
    System.out.println("  protect <input-file> <key-file> <output-file>");
    System.out.println("    Encrypt a file using specified key file");
    
    System.out.println("  unprotect <input-file> <key-file> <output-file>");
    System.out.println("    Decrypt a file using specified key file");
    
    System.out.println("  check <input-file>");
    System.out.println("    Verify the integrity of specified file");
    
    System.out.println("  public-info <carID> <host> <port>");
    System.out.println("    Fetch public information about specified car");
    
    System.out.println("  audit <carID> <host> <port>");
    System.out.println("    View encrypted audit trail of configuration actions for specified car");

    System.out.println("  give-key <host> <port>");
    System.out.println("    Give key to the mechanic to autorise him to see the configuration");
    
    System.out.println("  exit");
    System.out.println("    Exit the CLI");

    System.out.println("\nExample Usage:");
    System.out.println("  connect localhost 5000 config.json");
    System.out.println("    Connect to local server on port 5000 with configuration file");
    
    System.out.println("  fetch CAR123 localhost 5000");
    System.out.println("    Fetch configuration for CAR123 from local server on port 5000");
    
    System.out.println("  get climate temperature");
    System.out.println("    Get temperature setting from climate category");
    
    System.out.println("  protect config.json key.pem encrypted.json");
    System.out.println("    Encrypt config.json using key.pem to encrypted.json");
    
    System.out.println("  audit CAR123 localhost 5000");
    System.out.println("    View audit trail for CAR123 from local server on port 5000");
}

}