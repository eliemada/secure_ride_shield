package pt.tecnico.motorist.car;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import javax.crypto.Cipher;
import javax.net.ssl.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

import pt.tecnico.motorist.AuditCrypto;
import pt.tecnico.motorist.Check;
import pt.tecnico.motorist.FirmwareCrypto;
import pt.tecnico.motorist.KeyLoader;
import pt.tecnico.motorist.Protect;
import pt.tecnico.motorist.Unprotect;

/**
 * The Car class represents a connected vehicle system that handles secure
 * configuration management,
 * firmware updates, and communication with users. It implements a secure server
 * that processes
 * encrypted messages, manages car configurations, and maintains an audit trail
 * of all operations.
 * 
 * This class uses both RSA and EC cryptography for securing communications and
 * verifying message
 * authenticity. It stores configurations and audit data in a SQLite database
 * and supports
 * multiple authorized users with different access levels.
 * 
 * Security features include:
 * - TLS encrypted communications
 * - RSA encryption for secure message exchange
 * - EC signatures for message authentication
 * - Secure storage of configurations
 * - Audit logging of all operations
 * - Secure firmware update verification
 * 
 * @see pt.tecnico.motorist.KeyLoader
 * @see pt.tecnico.motorist.FirmwareCrypto
 */
public class Car {
    /** Database URL for SQLite connection */
    private static final String DB_URL = "jdbc:sqlite:src/main/resources/db/car_config.db";

    /** Gson instance for JSON processing */
    private static final Gson gson = new Gson();

    // Initialize BouncyCastle security provider
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // Configuration fields
    private String carID;
    private String userID;
    private JsonObject privateConfiguration;
    private JsonObject publicCarInfo;
    private boolean saveToDb = true;

    // Cryptographic keys
    private PublicKey carRsaPublicKey;
    private PrivateKey carRsaPrivateKey;
    private PrivateKey carEcPrivateKey;
    private Map<String, PublicKey> userRsaPublicKeys;
    private Map<String, PublicKey> userEcPublicKeys;

    /**
     * Constructs a new Car instance with the specified cryptographic keys.
     * Initializes security components and verifies key pairs for integrity.
     * 
     * @param carRsaPrivateKey The car's RSA private key for decryption
     * @param carRsaPublicKey  The car's RSA public key for verification
     * @param carEcPrivateKey  The car's EC private key for signing
     * @throws SecurityException        if key validation fails or initialization
     *                                  fails
     * @throws IllegalArgumentException if any key parameter is null
     */
    public Car(PrivateKey carRsaPrivateKey, PublicKey carRsaPublicKey, PrivateKey carEcPrivateKey)
            throws SecurityException {
        try {
            // Validate inputs
            if (carRsaPrivateKey == null) {
                throw new IllegalArgumentException("Car RSA private key cannot be null");
            }
            if (carRsaPublicKey == null) {
                throw new IllegalArgumentException("Car RSA public key cannot be null");
            }
            if (carEcPrivateKey == null) {
                throw new IllegalArgumentException("Car EC private key cannot be null");
            }

            // Verify RSA key pair matches mathematically
            verifyKeyPair(carRsaPrivateKey, carRsaPublicKey);

            // Initialize all fields
            this.carRsaPrivateKey = carRsaPrivateKey;
            this.carRsaPublicKey = carRsaPublicKey;
            this.carEcPrivateKey = carEcPrivateKey;
            this.privateConfiguration = new JsonObject();
            this.publicCarInfo = new JsonObject();
            this.userRsaPublicKeys = new HashMap<>();
            this.userEcPublicKeys = new HashMap<>();
            this.carID = "1234XYZ"; // Default car ID

            // Initialize car info
            updatePublicCarInfo();

        } catch (SecurityException e) {
            System.err.println("[Car Error] Security initialization failed: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.err.println("[Car Error] Initialization failed: " + e.getMessage());
            throw new SecurityException("Failed to initialize car: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies that an RSA key pair matches mathematically and functionally.
     * Performs both mathematical verification of key components and an
     * encryption/decryption test to ensure the keys work correctly together.
     * 
     * @param privateKey The RSA private key to verify
     * @param publicKey  The RSA public key to verify against the private key
     * @throws SecurityException if the keys don't match or the test fails
     * @throws Exception         if any cryptographic operation fails
     */
    private void verifyKeyPair(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // Mathematical verification of key components
        if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey &&
                publicKey instanceof java.security.interfaces.RSAPublicKey) {

            java.security.interfaces.RSAPrivateCrtKey rsaPrivKey = (java.security.interfaces.RSAPrivateCrtKey) privateKey;
            java.security.interfaces.RSAPublicKey rsaPubKey = (java.security.interfaces.RSAPublicKey) publicKey;

            // Compare modulus values
            if (!rsaPrivKey.getModulus().equals(rsaPubKey.getModulus())) {
                System.out.println("[Car Debug] Key modulus mismatch!");
                System.out.println("Private key modulus: " + rsaPrivKey.getModulus().toString(16));
                System.out.println("Public key modulus: " + rsaPubKey.getModulus().toString(16));
                throw new SecurityException("RSA key pair mismatch - modulus values are different");
            }

            // Compare public exponents
            if (!rsaPrivKey.getPublicExponent().equals(rsaPubKey.getPublicExponent())) {
                System.out.println("[Car Debug] Public exponent mismatch!");
                System.out.println("Private key public exponent: " + rsaPrivKey.getPublicExponent().toString(16));
                System.out.println("Public key exponent: " + rsaPubKey.getPublicExponent().toString(16));
                throw new SecurityException("RSA key pair mismatch - public exponents are different");
            }
        }

        // Functional verification through encryption/decryption test
        try {
            byte[] testData = "test".getBytes();

            // Use Java default provider for basic RSA operation
            Cipher basicCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // Test encryption with public key
            basicCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = basicCipher.doFinal(testData);

            // Test decryption with private key
            basicCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = basicCipher.doFinal(encrypted);

            // Verify decrypted data matches original
            if (!java.util.Arrays.equals(testData, decrypted)) {
                throw new SecurityException("RSA test failed - decrypted data doesn't match original");
            }

        } catch (Exception e) {
            System.out.println("[Car Debug] Encryption/decryption test failed: " + e.getMessage());
            if (e.getCause() != null) {
                System.out.println("[Car Debug] Cause: " + e.getCause().getMessage());
                e.getCause().printStackTrace();
            }
            throw new SecurityException("RSA key pair verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Updates the public car information with current sensor data.
     * This method would typically read from actual car sensors in a production
     * environment.
     * Currently uses mock data for demonstration purposes.
     */
    private void updatePublicCarInfo() {
        this.publicCarInfo = new JsonObject();
        this.publicCarInfo.addProperty("battery_level", "75%");
        this.publicCarInfo.addProperty("total_mileage", "15000");
        this.publicCarInfo.addProperty("last_update", java.time.Instant.now().toString());
    }

    /**
     * Retrieves the current public information about the car.
     * Updates the information before returning to ensure fresh data.
     * 
     * @return JsonObject containing public car information like battery level and
     *         mileage
     */
    public JsonObject getPublicCarInfo() {
        updatePublicCarInfo();
        return this.publicCarInfo;
    }

    /**
     * Controls whether configuration changes are saved to the database.
     * Useful for testing scenarios where persistent storage is not desired.
     * 
     * @param save true to enable database storage, false to disable
     */
    public void setSaveToDb(boolean save) {
        this.saveToDb = save;
    }

    /**
     * Updates the car's local configuration from a JSON configuration object.
     * Processes both public and private configuration settings.
     * 
     * @param configJson The JSON configuration object containing car settings
     */
    private void updateLocalConfiguration(JsonObject configJson) {
        this.carID = configJson.get("carID").getAsString();
        this.userID = configJson.get("user").getAsString();

        // Process private configuration settings if present
        if (configJson.has("private_configuration")) {
            this.privateConfiguration = configJson.getAsJsonObject("private_configuration");

            // Process AC settings
            if (privateConfiguration.has("ac")) {
                JsonArray acConfig = privateConfiguration.getAsJsonArray("ac");
                for (int i = 0; i < acConfig.size(); i++) {
                    JsonObject acSetting = acConfig.get(i).getAsJsonObject();
                    System.out.println("AC Setting " + (i + 1) + ": " + acSetting.toString());
                }
            }

            // Process seat settings
            if (privateConfiguration.has("seat")) {
                JsonArray seatConfig = privateConfiguration.getAsJsonArray("seat");
                for (int i = 0; i < seatConfig.size(); i++) {
                    JsonObject seatSetting = seatConfig.get(i).getAsJsonObject();
                    System.out.println("Seat Setting " + (i + 1) + ": " + seatSetting.toString());
                }
            }
        }
    }

    /**
     * Stores a secure message in the database for audit purposes.
     * Validates all inputs and maintains message ordering through message numbers.
     * 
     * @param carID                    The ID of the car
     * @param originalEncryptedMessage The original encrypted message
     * @param userID                   The ID of the user who sent the message
     * @param originalSignature        The original message signature
     * @throws IllegalArgumentException if any parameter is null or empty
     * @throws Exception                if database operation fails
     */
    public void storeSecureMessage(String carID, String originalEncryptedMessage, String userID,
            String originalSignature)
            throws Exception {
        if (!saveToDb) {
            System.out.println("Database storage is disabled.");
            return;
        }

        // Input validation
        if (carID == null || carID.trim().isEmpty()) {
            throw new IllegalArgumentException("CarID cannot be null or empty");
        }
        if (originalEncryptedMessage == null || originalEncryptedMessage.trim().isEmpty()) {
            throw new IllegalArgumentException("Encrypted message cannot be null or empty");
        }
        if (userID == null || userID.trim().isEmpty()) {
            throw new IllegalArgumentException("UserID cannot be null or empty");
        }
        if (originalSignature == null || originalSignature.trim().isEmpty()) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }

        // Get current timestamp for audit trail
        String timestamp = java.time.Instant.now().toString();

        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            // Store message with sequential message number
            String sql = "INSERT INTO secure_messages (carID, userId, message, action_type, timestamp, signature, message_number) VALUES (?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, carID);
                stmt.setString(2, userID);
                stmt.setString(3, originalEncryptedMessage);
                stmt.setString(4, "CONFIG_UPDATE");
                stmt.setString(5, timestamp);
                stmt.setString(6, originalSignature);

                // Get next message number for this user-car pair
                int messageNumber = getNextMessageNumber(conn, carID, userID);
                stmt.setInt(7, messageNumber);

                int rows = stmt.executeUpdate();
                System.out.println("Stored " + rows + " row(s) in database.");
            }
        } catch (Exception e) {
            System.err.println("Database error while storing message: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Retrieves the next sequential message number for a given car-user pair.
     * Ensures message ordering in the audit trail.
     * 
     * @param conn   Active database connection
     * @param carID  The ID of the car
     * @param userID The ID of the user
     * @return The next available message number
     * @throws Exception if database query fails
     */
    private int getNextMessageNumber(Connection conn, String carID, String userID) throws Exception {
        String sql = "SELECT MAX(message_number) FROM secure_messages WHERE carID = ? AND userId = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, carID);
            stmt.setString(2, userID);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) + 1;
            }
            return 1; // First message for this car-user pair
        }
    }

    /**
     * Processes an encrypted message containing configuration updates.
     * The method verifies the signature, decrypts the message, updates local
     * configuration,
     * and stores the secure message for audit purposes.
     *
     * @param inputFile        Path to the file containing the encrypted message
     * @param tempFile         Path to a temporary file used during decryption
     * @param ownerEcPublicKey The EC public key of the message owner for signature
     *                         verification
     * @throws SecurityException If message signature verification fails
     * @throws Exception         If any error occurs during message processing
     */
    public void processMessage(String inputFile, String tempFile, PublicKey ownerEcPublicKey) throws Exception {
        // First, verify the signature using Owner's EC public key
        if (!Check.check(inputFile, ownerEcPublicKey)) {
            throw new SecurityException("Message signature verification failed!");
        }

        // Read the original encrypted message and signature
        JsonObject messageJson;
        try (FileReader reader = new FileReader(inputFile)) {
            messageJson = gson.fromJson(reader, JsonObject.class);
        }

        // Store original values before decryption for audit purposes
        String originalSignature = messageJson.get("signature").getAsString();
        String originalEncryptedMessage = gson.toJson(messageJson);

        // Unprotect (decrypt) the message using Car's RSA private key
        Unprotect.unprotect(inputFile, tempFile, carRsaPrivateKey);

        // Read and parse the unprotected (decrypted) configuration
        JsonObject configJson;
        try (FileReader reader = new FileReader(tempFile)) {
            configJson = gson.fromJson(reader, JsonObject.class);
        }

        // Apply the new configuration locally
        updateLocalConfiguration(configJson);

        // Store the original encrypted message and signature for audit trail
        storeSecureMessage(this.carID, originalEncryptedMessage, this.userID, originalSignature);

        // Clean up temporary file to prevent sensitive data leakage
        new File(tempFile).delete();
    }

    /**
     * Creates and configures an SSL server socket with mutual authentication
     * enabled.
     * The socket uses TLS 1.3 and requires client authentication.
     *
     * @param port The port number on which to create the server socket
     * @return A configured SSLServerSocket instance
     * @throws Exception If any error occurs during socket creation or configuration
     */
    public static SSLServerSocket createSSLServerSocket(int port) throws Exception {
        // Load the server's keystore containing its certificate and private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/server.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        // Load the truststore containing trusted client certificates
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/servertruststore.jks")) {
            trustStore.load(trustStoreIS, "changeme".toCharArray());
        }

        // Initialize key manager factory with server's keystore
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeme".toCharArray());

        // Initialize trust manager factory with server's truststore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create SSL context with TLS 1.3 protocol
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Create and configure the SSL server socket
        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
        sslServerSocket.setNeedClientAuth(true); // Require client authentication

        return sslServerSocket;
    }

    /**
     * Processes and verifies a firmware update package from the manufacturer.
     * Performs signature verification, checks required fields, and attempts
     * decryption.
     * All operations are logged for audit purposes.
     *
     * @param firmwareJson          The firmware update package as a JSON string
     * @param manufacturerPublicKey The manufacturer's public key for signature
     *                              verification
     * @throws SecurityException        If signature verification fails or
     *                                  decryption fails
     * @throws IllegalArgumentException If required fields are missing
     * @throws Exception                If any other error occurs during processing
     */
    private void handleFirmwareUpdate(String firmwareJson, PublicKey manufacturerPublicKey) throws Exception {
        JsonObject firmware = null;
        try {
            // Parse firmware JSON first to access metadata even if verification fails
            firmware = gson.fromJson(firmwareJson, JsonObject.class);

            // Verify manufacturer's signature before processing
            if (!FirmwareCrypto.check(firmwareJson, manufacturerPublicKey)) {
                logFirmwareUpdate(firmware, "FAILED", "Invalid firmware signature");
                throw new SecurityException("Invalid firmware signature");
            }

            // Verify all required fields are present in the firmware package
            String[] requiredFields = { "cipherText", "encryptedAesKey", "iv", "signature", "firmwareID", "version" };
            for (String field : requiredFields) {
                if (!firmware.has(field)) {
                    String error = "Missing required firmware field: " + field;
                    logFirmwareUpdate(firmware, "FAILED", error);
                    throw new IllegalArgumentException(error);
                }
            }

            try {
                // Attempt to decrypt firmware using car's RSA private key
                String decryptedFirmware = FirmwareCrypto.unprotect(firmwareJson, carRsaPrivateKey);
                JsonObject decryptedFirmwareJson = gson.fromJson(decryptedFirmware, JsonObject.class);

                // Log successful update for audit trail
                logFirmwareUpdate(firmware, "SUCCESS", null);

                // Debug logging of successful update details
                System.out.println("[Car Debug] Firmware update successful:");
                System.out.println("  - Firmware ID: " + firmware.get("firmwareID").getAsString());
                System.out.println("  - Version: " + firmware.get("version").getAsString());
                System.out.println("  - Timestamp: " + firmware.get("timestamp").getAsString());

            } catch (Exception e) {
                String error = "Error decrypting firmware: " + e.getMessage();
                logFirmwareUpdate(firmware, "FAILED", error);
                throw new SecurityException(error);
            }
        } catch (Exception e) {
            if (firmware != null) {
                logFirmwareUpdate(firmware, "FAILED", e.getMessage());
            }
            System.out.println("[Car Debug] Firmware update failed: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Retrieves the secure configuration for a specific car and user.
     * The configuration is re-encrypted for the requesting user if they have
     * access.
     *
     * @param carId            The ID of the car whose configuration is being
     *                         requested
     * @param requestingUserId The ID of the user requesting the configuration
     * @return The encrypted configuration or status message
     * @throws SecurityException If the requesting user's public key is not found
     * @throws Exception         If any error occurs during retrieval or processing
     */
    public String getSecureConfiguration(String carId, String requestingUserId) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            int messageNumber = getNextMessageNumber(conn, carId, requestingUserId);

            // Check for configurations specific to this user
            String checkSql = "SELECT message FROM secure_messages WHERE carID = ? AND userId = ? AND action_type = 'CONFIG_UPDATE' ORDER BY timestamp DESC LIMIT 1";
            PreparedStatement checkStmt = conn.prepareStatement(checkSql);
            checkStmt.setString(1, carId);
            checkStmt.setString(2, requestingUserId);

            ResultSet checkRs = checkStmt.executeQuery();
            if (checkRs.next()) {
                // Configuration found for this user - prepare for re-encryption
                Unprotect.setDatabaseFetchMode(true);

                String storedMessage = checkRs.getString("message");

                // Create temporary files for encryption process
                String tempEncrypted = "temp_encrypted_" + System.currentTimeMillis() + ".json";
                String tempDecrypted = "temp_decrypted_" + System.currentTimeMillis() + ".json";
                String tempReEncrypted = "temp_reencrypted_" + System.currentTimeMillis() + ".json";

                try {
                    // Write stored encrypted message to temporary file
                    try (FileWriter writer = new FileWriter(tempEncrypted)) {
                        writer.write(storedMessage);
                    }

                    // Decrypt stored message using car's RSA private key
                    Unprotect.unprotect(tempEncrypted, tempDecrypted, carRsaPrivateKey);

                    // Re-encrypt for the requesting user with their RSA public key
                    PublicKey userRsaPublicKey = userRsaPublicKeys.get(requestingUserId);
                    if (userRsaPublicKey == null) {
                        throw new SecurityException("No public key found for user: " + requestingUserId);
                    }

                    Protect.protect(tempDecrypted, tempReEncrypted, carEcPrivateKey, userRsaPublicKey);

                    // Read the re-encrypted message
                    String freshMessage;
                    try (FileReader reader = new FileReader(tempReEncrypted)) {
                        JsonObject messageJson = gson.fromJson(reader, JsonObject.class);
                        freshMessage = gson.toJson(messageJson);
                    }

                    // Log the configuration read access for audit trail
                    String logSql = "INSERT INTO secure_messages (carID, userId, message, action_type, timestamp, signature, message_number) VALUES (?, ?, ?, ?, ?, ?, ?)";
                    PreparedStatement logStmt = conn.prepareStatement(logSql);
                    logStmt.setString(1, carId);
                    logStmt.setString(2, requestingUserId);
                    logStmt.setString(3, "CONFIG_READ");
                    logStmt.setString(4, "CONFIG_READ");
                    logStmt.setString(5, java.time.Instant.now().toString());
                    logStmt.setString(6, "READ_ACCESS");
                    logStmt.setInt(7, messageNumber);
                    logStmt.executeUpdate();

                    return freshMessage;
                } finally {
                    // Clean up temporary files to prevent sensitive data leakage
                    Unprotect.setDatabaseFetchMode(false);
                    new File(tempEncrypted).delete();
                    new File(tempDecrypted).delete();
                    new File(tempReEncrypted).delete();
                }
            }

            // If no config found for this user, check if any configs exist for the car
            String countSql = "SELECT userId FROM secure_messages WHERE carID = ? AND action_type = 'CONFIG_UPDATE' ORDER BY timestamp DESC LIMIT 1";
            PreparedStatement countStmt = conn.prepareStatement(countSql);
            countStmt.setString(1, carId);

            ResultSet countRs = countStmt.executeQuery();
            if (countRs.next()) {
                String configOwner = countRs.getString("userId");
                return "CONFIG_EXISTS:" + configOwner;
            }

            return "NO_CONFIG";
        }
    }

    /**
     * Starts the secure server and handles client connections.
     * Loads necessary public keys and processes various types of client requests
     * including:
     * - Public information requests
     * - Configuration fetches
     * - Audit requests
     * - Firmware updates
     * - Configuration updates
     *
     * @param port The port number on which to start the server
     * @throws Exception If any error occurs during server startup or operation
     */
    public void startServer(int port) throws Exception {
        // Load public keys for all authorized users
        try {
            // Load user1 keys (both EC for signatures and RSA for encryption)
            userEcPublicKeys.put("user1", KeyLoader.loadECPublicKey(
                    "src/main/resources/keys/owner_ec_public.pem"));
            userRsaPublicKeys.put("user1", KeyLoader.loadRSAPublicKey(
                    "src/main/resources/keys/owner_rsa_public.pem"));

            // Load user2 keys
            userEcPublicKeys.put("user2", KeyLoader.loadECPublicKey(
                    "src/main/resources/keys/owner2_ec_public.pem"));
            userRsaPublicKeys.put("user2", KeyLoader.loadRSAPublicKey(
                    "src/main/resources/keys/owner2_rsa_public.pem"));

            System.out.println("Loaded public keys for users: " + String.join(", ", userEcPublicKeys.keySet()));
        } catch (Exception e) {
            System.err.println("Failed to load user public keys: " + e.getMessage());
            throw e;
        }

        // Create SSL server socket and start accepting connections
        try (SSLServerSocket listener = createSSLServerSocket(port)) {
            System.out.println("Car server is running. Waiting for client connections...");

            while (true) {
                try (Socket socket = listener.accept()) {
                    InputStream is = socket.getInputStream();
                    byte[] data = new byte[4096];
                    int len = is.read(data);
                    if (len == -1)
                        continue;

                    String message = new String(data, 0, len);
                    OutputStream os = socket.getOutputStream();
                    System.out.println("Received message: " + message);

                    // Handle different types of requests based on message prefix
                    if (message.startsWith("FETCH_PUBLIC:")) {
                        // Handle public information request
                        String[] parts = message.substring(12).split(":");
                        String carId = parts[0];

                        // Create response JSON using existing publicCarInfo
                        JsonObject response = new JsonObject();
                        response.addProperty("carID", carId);
                        response.add("public_car_info", getPublicCarInfo());

                        String jsonResponse = gson.toJson(response);
                        os.write(jsonResponse.getBytes());
                        os.flush();
                    } else if (message.startsWith("FETCH:")) {
                        // Handle configuration fetch request
                        String[] parts = message.substring(6).split(":");
                        String carId = parts[0];
                        String requestingUserId = parts[1];
                        String config = getSecureConfiguration(carId, requestingUserId);

                        if (config != null) {
                            os.write(config.getBytes());
                        } else {
                            os.write("NO_CONFIG".getBytes());
                        }
                        os.flush();

                    } else if (message.startsWith("AUDIT:")) {
                        // Handle audit request
                        String[] parts = message.substring(6).split(":");
                        String carId = parts[0];
                        String requestingUserId = parts[1];
                        String auditData = handleAuditRequest(carId, requestingUserId);
                        if (auditData != null) {
                            os.write(auditData.getBytes());
                        } else {
                            os.write("ERROR:No audit data available".getBytes());
                        }
                        os.flush();
                    } else if (message.startsWith("FIRMWARE:")) {
                        // Handle firmware update
                        String firmwareJson = message.substring(9); // Skip "FIRMWARE:" prefix
                        System.out.println("Car received firmware update: " + firmwareJson.substring(0, 100) + "...");
                        try {
                            // Load manufacturer's public key for verification
                            PublicKey manufacturerPublicKey = KeyLoader.loadECPublicKey(
                                    "src/main/resources/keys/manufacturer_public_key_x509.pem");

                            handleFirmwareUpdate(firmwareJson, manufacturerPublicKey);

                            JsonObject response = new JsonObject();
                            response.addProperty("status", "success");
                            response.addProperty("message", "Firmware update processed successfully");
                            os.write(gson.toJson(response).getBytes());

                        } catch (Exception e) {
                            JsonObject response = new JsonObject();
                            response.addProperty("status", "error");
                            response.addProperty("message", "Error processing firmware update: " + e.getMessage());
                            os.write(gson.toJson(response).getBytes());
                        }
                        os.flush();
                    } else {
                        // Handle configuration update
                        String tempInputFile = "temp_input_" + System.currentTimeMillis() + ".json";
                        String tempOutputFile = "temp_output_" + System.currentTimeMillis() + ".json";

                        try {
                            JsonObject receivedJson = gson.fromJson(message, JsonObject.class);
                            if (receivedJson == null) {
                                throw new IllegalArgumentException("Invalid JSON format");
                            }

                            if (!receivedJson.has("sender")) {
                                throw new IllegalArgumentException("Missing 'sender' field in message");
                            }

                            String userId = receivedJson.get("sender").getAsString();
                            PublicKey userEcPublicKey = userEcPublicKeys.get(userId);

                            if (userEcPublicKey == null) {
                                throw new SecurityException("No public key found for user: " + userId);
                            }

                            // Write received message to temp file
                            try (FileWriter writer = new FileWriter(tempInputFile)) {
                                writer.write(message);
                            }

                            // Process message
                            processMessage(tempInputFile, tempOutputFile, userEcPublicKey);

                            os.write("Configuration processed and stored successfully.".getBytes());
                            os.flush();

                        } catch (Exception e) {
                            String errorMsg = "Error processing message: " + e.getMessage();
                            System.err.println(errorMsg);
                            os.write(("ERROR: " + errorMsg).getBytes());
                            os.flush();
                        } finally {
                            new File(tempInputFile).delete();
                            new File(tempOutputFile).delete();
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Error handling client connection: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Processes an audit request for a specific car and user, retrieving and
     * verifying
     * the audit trail of configuration and firmware updates.
     *
     * @param carId            The unique identifier of the car
     * @param requestingUserId The ID of the user requesting the audit
     * @return A protected (encrypted and signed) JSON string containing the audit
     *         trail
     * @throws SecurityException If the user lacks appropriate access rights or if
     *                           security verification fails
     * @throws Exception         For database connectivity issues or other
     *                           processing errors
     */
    private String handleAuditRequest(String carId, String requestingUserId) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            // Verify user has configuration access rights for the specified car
            String accessSql = "SELECT COUNT(*) as count FROM secure_messages " +
                    "WHERE carID = ? AND userId = ? AND action_type = 'CONFIG_UPDATE'";
            PreparedStatement accessStmt = conn.prepareStatement(accessSql);
            accessStmt.setString(1, carId);
            accessStmt.setString(2, requestingUserId);

            ResultSet accessRs = accessStmt.executeQuery();
            if (!accessRs.next() || accessRs.getInt("count") == 0) {
                throw new SecurityException("No configuration access rights for user " + requestingUserId);
            }

            // Query to retrieve relevant security events (config and firmware updates)
            String sql = "SELECT message, action_type, timestamp, signature, userId, message_number " +
                    "FROM secure_messages " +
                    "WHERE carID = ? " +
                    "AND (action_type IN ('CONFIG_UPDATE', 'CONFIG_READ', 'FIRMWARE_UPDATE')) " +
                    "ORDER BY timestamp DESC";

            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, carId);
            ResultSet rs = stmt.executeQuery();

            JsonObject response = new JsonObject();
            JsonArray entries = new JsonArray();

            while (rs.next()) {
                JsonObject entry = new JsonObject();
                String action = rs.getString("action_type");
                String timestamp = rs.getString("timestamp");
                String originalSignature = rs.getString("signature");
                String originalMessage = rs.getString("message");
                String userId = rs.getString("userId");
                int messageNumber = rs.getInt("message_number");

                // Populate basic audit information
                entry.addProperty("action", action);
                entry.addProperty("timestamp", timestamp);
                entry.addProperty("user", userId);
                entry.addProperty("message_number", messageNumber);

                // Process different types of audit entries based on action type
                if ("FIRMWARE_UPDATE".equals(action)) {
                    try {
                        // Parse stored firmware metadata JSON
                        JsonObject metadata = gson.fromJson(originalMessage, JsonObject.class);

                        JsonObject firmwareInfo = new JsonObject();

                        // Handle both legacy and new firmware message formats
                        JsonObject firmware = null;
                        if (metadata.has("firmware")) {
                            // New format with metadata wrapper
                            firmware = metadata.getAsJsonObject("firmware");
                        } else if (metadata.has("firmwareID")) {
                            // Legacy format with direct firmware object
                            firmware = metadata;
                        }

                        if (firmware != null) {
                            firmwareInfo.addProperty("firmwareID", firmware.get("firmwareID").getAsString());
                            firmwareInfo.addProperty("version", firmware.get("version").getAsString());
                        }

                        // Include firmware update status and any error information
                        if (metadata.has("status")) {
                            firmwareInfo.addProperty("status", metadata.get("status").getAsString());
                            if (metadata.has("error_message")) {
                                firmwareInfo.addProperty("error_message", metadata.get("error_message").getAsString());
                            }
                        }

                        entry.add("firmware_details", firmwareInfo);
                        entry.addProperty("signature_valid", true); // Firmware signatures are verified at reception
                        System.out.println("[Audit] Processed firmware update entry: " + firmwareInfo.toString());

                    } catch (Exception e) {
                        entry.addProperty("error", "Failed to parse firmware update details: " + e.getMessage());
                        System.err.println("[Audit Error] Error processing firmware entry: " + e.getMessage());
                        e.printStackTrace();
                    }

                } else if ("CONFIG_UPDATE".equals(action)) {
                    try {
                        // Verify user's public key is available
                        PublicKey userEcPublicKey = userEcPublicKeys.get(userId);
                        if (userEcPublicKey == null) {
                            throw new SecurityException("No public key found for user: " + userId);
                        }

                        // Validate message structure
                        JsonObject messageJson = gson.fromJson(originalMessage, JsonObject.class);
                        if (!messageJson.has("signature")) {
                            System.out.println("[Audit Warning] Stored message does not contain signature field");
                        }

                        // Verify message signature
                        Check.setAuditMode(true);
                        boolean isValid = Check.verifyStoredMessage(originalMessage, originalSignature,
                                userEcPublicKey);
                        Check.setAuditMode(false);
                        System.out.println("[Audit] Signature verification for config update: " + isValid);

                        entry.addProperty("signature_valid", isValid);

                        // For the requesting user's own messages, decrypt and include configuration
                        // summary
                        if (isValid && userId.equals(requestingUserId)) {
                            String tempEncrypted = "temp_" + System.currentTimeMillis() + ".json";
                            String tempDecrypted = "temp_decrypted_" + System.currentTimeMillis() + ".json";

                            try {
                                // Create temporary file with encrypted content
                                try (FileWriter writer = new FileWriter(tempEncrypted)) {
                                    writer.write(originalMessage);
                                }

                                // Decrypt configuration using car's private key
                                Unprotect.setDatabaseFetchMode(true);
                                Unprotect.unprotect(tempEncrypted, tempDecrypted, carRsaPrivateKey);
                                Unprotect.setDatabaseFetchMode(false);

                                // Parse and summarize decrypted configuration
                                JsonObject config;
                                try (FileReader reader = new FileReader(tempDecrypted)) {
                                    config = gson.fromJson(reader, JsonObject.class);
                                }

                                if (config != null && config.has("private_configuration")) {
                                    JsonObject configSummary = new JsonObject();
                                    JsonObject privateConfig = config.getAsJsonObject("private_configuration");
                                    for (String category : privateConfig.keySet()) {
                                        configSummary.addProperty(category, "Modified");
                                    }
                                    entry.add("configuration_changes", configSummary);
                                }
                            } finally {
                                // Cleanup temporary files
                                new File(tempEncrypted).delete();
                                new File(tempDecrypted).delete();
                            }
                        }
                    } catch (Exception e) {
                        entry.addProperty("verification_error", e.getMessage());
                        System.err.println("[Audit Error] Error processing config entry: " + e.getMessage());
                    }
                }

                entries.add(entry);
            }

            response.add("audit_entries", entries);

            // Add audit metadata
            JsonObject metadata = new JsonObject();
            metadata.addProperty("car_id", carId);
            metadata.addProperty("requesting_user", requestingUserId);
            metadata.addProperty("audit_timestamp", java.time.Instant.now().toString());
            metadata.addProperty("total_entries", entries.size());
            response.add("audit_metadata", metadata);

            // Convert audit trail to JSON string
            String auditTrail = gson.toJson(response);

            // Retrieve requesting user's public key
            PublicKey userRsaPublicKey = userRsaPublicKeys.get(requestingUserId);
            if (userRsaPublicKey == null) {
                System.err.println("[Audit Error] No RSA public key found for user: " + requestingUserId);
                throw new SecurityException("No public key found for user: " + requestingUserId);
            }

            // Generate security parameters
            long timestamp = System.currentTimeMillis();
            String nonce = java.util.UUID.randomUUID().toString();

            // Encrypt and sign the audit trail
            String protectedAudit = AuditCrypto.protect(auditTrail, carEcPrivateKey, userRsaPublicKey, timestamp,
                    nonce);
            return protectedAudit;
        }
    }

    /**
     * Logs a firmware update event to the secure message database, including status
     * and any error information.
     *
     * @param firmware     JsonObject containing firmware update details including
     *                     ID,
     *                     version, and signature
     * @param status       Current status of the firmware update process
     * @param errorMessage Optional error message if the update failed
     * @throws Exception If database operations fail or required firmware
     *                   information
     *                   is missing
     */
    private void logFirmwareUpdate(JsonObject firmware, String status, String errorMessage) throws Exception {
        if (!saveToDb) {
            System.out.println("Database storage is disabled.");
            return;
        }

        // Extract required firmware information
        String firmwareId = firmware.get("firmwareID").getAsString();
        String version = firmware.get("version").getAsString();
        String timestamp = java.time.Instant.now().toString();
        String nonce = firmware.get("nonce").getAsString();

        // Create metadata wrapper for firmware information
        JsonObject metadata = new JsonObject();
        metadata.add("firmware", firmware);
        metadata.addProperty("status", status);
        if (errorMessage != null) {
            metadata.addProperty("error_message", errorMessage);
        }

        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String sql = "INSERT INTO secure_messages (carID, userId, message, action_type, timestamp, signature, message_number) "
                    +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)";

            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, this.carID != null ? this.carID : "unknown");
                stmt.setString(2, "manufacturer"); // Firmware updates are always from manufacturer
                stmt.setString(3, gson.toJson(metadata));
                stmt.setString(4, "FIRMWARE_UPDATE");
                stmt.setString(5, timestamp);
                stmt.setString(6, firmware.get("signature").getAsString());
                stmt.setInt(7, getNextMessageNumber(conn, this.carID != null ? this.carID : "unknown", "manufacturer"));

                int rows = stmt.executeUpdate();
                System.out.println("[Car Debug] Logged firmware update: ID=" + firmwareId +
                        ", Version=" + version);
            }
        } catch (Exception e) {
            System.err.println("[Car Error] Failed to log firmware update: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Entry point for the Car server application. Initializes the car instance with
     * required security keys and starts the server.
     *
     * @param args Command line arguments. First argument (optional) specifies the
     *             port
     *             number, defaults to 5000
     * @throws Exception If initialization fails or server cannot be started
     */
    public static void main(String[] args) throws Exception {
        try {
            // Load required security keys for the car
            PrivateKey carRsaPrivateKey = KeyLoader.loadRSAPrivateKey(
                    "src/main/resources/keys/car_rsa_private_pkcs8.pem");
            PublicKey carRsaPublicKey = KeyLoader.loadRSAPublicKey(
                    "src/main/resources/keys/car_rsa_public.pem");
            PrivateKey carEcPrivateKey = KeyLoader.loadECPrivateKey(
                    "src/main/resources/keys/car_ec_private_pkcs8.pem");

            // Initialize car instance
            Car car = new Car(carRsaPrivateKey, carRsaPublicKey, carEcPrivateKey);

            // Parse port from command line or use default
            int port = args.length > 0 ? Integer.parseInt(args[0]) : 5000;

            System.out.println("Starting car server with required keys loaded...");
            car.startServer(port);

        } catch (Exception e) {
            System.err.println("Failed to initialize car server: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
}