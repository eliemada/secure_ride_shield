package pt.tecnico.motorist.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import java.security.Signature;
import java.util.Base64;

import pt.tecnico.motorist.Protect;
import pt.tecnico.motorist.Unprotect;
import pt.tecnico.motorist.Check;
import pt.tecnico.motorist.KeyLoader;

/**
 * The User class represents a client entity in the motorist system that can
 * interact with car configurations.
 * It provides functionality for secure communication with cars, including
 * fetching and sending encrypted
 * configuration data over SSL/TLS connections.
 * 
 * This class handles:
 * - Secure SSL socket creation
 * - Configuration fetch operations (both public and private)
 * - Secure message sending
 * - Configuration data management
 */
public class User {
    private String userId;
    private JsonObject lastFetchedConfig;
    private static final Gson gson = new Gson();

    /**
     * Constructs a new User instance with the specified user ID.
     *
     * @param userId The unique identifier for the user
     */
    public User(String userId) {
        this.userId = userId;
    }

    /**
     * Retrieves the user's ID.
     *
     * @return The user's ID string
     */
    public String getUserId() {
        return this.userId;
    }

    /**
     * Creates an SSL socket with mutual authentication using client certificates.
     * Loads keystores and trust stores from predefined locations and establishes
     * a TLS 1.3 connection.
     *
     * @param host The target host to connect to
     * @param port The port number for the connection
     * @return A configured SSLSocket ready for communication
     * @throws Exception If there are any issues with SSL configuration or
     *                   connection
     */
    public static SSLSocket createSSLSocket(String host, int port) throws Exception {
        // Load the keystore containing the client's certificate and private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/user.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        // Load the truststore containing trusted CA certificates
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/usertruststore.jks")) {
            trustStore.load(trustStoreIS, "changeme".toCharArray());
        }

        // Initialize key manager factory with the keystore
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeme".toCharArray());

        // Initialize trust manager factory with the truststore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create and initialize SSL context with TLS 1.3
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();
        return (SSLSocket) factory.createSocket(host, port);
    }

    /**
     * Convenience method to fetch full configuration with default settings.
     *
     * @param host              The target host address
     * @param port              The target port number
     * @param carId             The identifier of the car to fetch configuration for
     * @param userRsaPrivateKey The user's RSA private key for decryption
     * @param carEcPublicKey    The car's EC public key for signature verification
     * @return JsonObject containing the car's configuration, or null if unavailable
     * @throws Exception If there are any communication or security issues
     */
    public JsonObject fetchConfiguration(String host, int port, String carId, PrivateKey userRsaPrivateKey,
            PublicKey carEcPublicKey)
            throws Exception {
        return fetchConfiguration(host, port, carId, userRsaPrivateKey, carEcPublicKey, false);
    }

    /**
     * Fetches car configuration from the server, with options for public-only or
     * full access.
     * Handles encryption, signature verification, and various response scenarios.
     *
     * @param host              The target host address
     * @param port              The target port number
     * @param carId             The identifier of the car to fetch configuration for
     * @param userRsaPrivateKey The user's RSA private key for decryption
     * @param carEcPublicKey    The car's EC public key for signature verification
     * @param publicOnly        If true, only fetch public information
     * @return JsonObject containing the car's configuration, or null if unavailable
     * @throws Exception         If there are any communication or security issues
     * @throws SecurityException If there are issues with encryption or signatures
     */
    public JsonObject fetchConfiguration(String host, int port, String carId, PrivateKey userRsaPrivateKey,
            PublicKey carEcPublicKey, boolean publicOnly) throws Exception {
        JsonObject config = null;
        try (SSLSocket socket = createSSLSocket(host, port)) {
            socket.startHandshake();

            // Prepare the fetch request based on access type
            String fetchRequest = publicOnly ? "FETCH_PUBLIC:" + carId + ":" + this.userId
                    : "FETCH:" + carId + ":" + this.userId;

            // Send the request
            OutputStream os = socket.getOutputStream();
            os.write(fetchRequest.getBytes());
            os.flush();

            // Read the response
            InputStream is = socket.getInputStream();
            byte[] data = new byte[8192];
            int len = is.read(data);

            if (len <= 0) {
                return null;
            }

            String response = new String(data, 0, len);

            // Handle case where configuration exists but belongs to another user
            if (response.startsWith("CONFIG_EXISTS:")) {
                String ownerUserId = response.split(":")[1];
                System.out.println("Configuration exists but belongs to user: " + ownerUserId);
                System.out.println("You can only access public information. Use 'public-info' command.");
                return null;
            }

            // Handle case where no configuration exists
            if ("NO_CONFIG".equals(response)) {
                if (publicOnly) {
                    // Return default public information for public-only requests
                    JsonObject defaultPublic = new JsonObject();
                    defaultPublic.addProperty("carID", carId);
                    JsonObject publicInfo = new JsonObject();
                    publicInfo.addProperty("battery_level", "75%");
                    publicInfo.addProperty("total_mileage", "15000");
                    publicInfo.addProperty("last_update", java.time.Instant.now().toString());
                    defaultPublic.add("public_car_info", publicInfo);
                    return defaultPublic;
                }
                System.out.println("No configuration found for car ID: " + carId);
                System.out.println("Use 'send-config' command to create a new configuration.");
                return null;
            }

            // Handle case where user doesn't have access
            if ("NO_ACCESS".equals(response)) {
                System.out.println("You don't have access to this car's private configuration.");
                System.out.println("Try using 'public-info' command to view public information only.");
                return null;
            }

            // Handle public-only requests directly
            if (publicOnly) {
                try {
                    config = JsonParser.parseString(response).getAsJsonObject();
                    this.lastFetchedConfig = config;
                    return config;
                } catch (Exception e) {
                    System.err.println(
                            "Error parsing public information: " + e.getMessage() + "\nResponse was: " + response);
                    return null;
                }
            }

            // Process full configuration with encryption and signatures
            String tempEncryptedFile = "temp_encrypted_" + System.currentTimeMillis() + ".json";
            String tempDecryptedFile = "temp_decrypted_" + System.currentTimeMillis() + ".json";

            try {
                // Save encrypted response to temporary file
                try (FileWriter writer = new FileWriter(tempEncryptedFile)) {
                    writer.write(response);
                }

                // Verify the signature before decryption
                if (!Check.check(tempEncryptedFile, carEcPublicKey)) {
                    throw new SecurityException("Message signature verification failed!");
                }

                // Decrypt the configuration
                try {
                    Unprotect.unprotect(tempEncryptedFile, tempDecryptedFile, userRsaPrivateKey);
                } catch (InvalidKeyException e) {
                    throw new SecurityException("Decryption failed - invalid key used");
                }

                // Parse the decrypted configuration
                try (FileReader reader = new FileReader(tempDecryptedFile)) {
                    StringBuilder content = new StringBuilder();
                    char[] buffer = new char[1024];
                    int read;
                    while ((read = reader.read(buffer)) != -1) {
                        content.append(buffer, 0, read);
                    }

                    try {
                        config = JsonParser.parseString(content.toString()).getAsJsonObject();
                        if (config == null) {
                            throw new IllegalStateException("Failed to parse decrypted configuration");
                        }
                        this.lastFetchedConfig = config;
                    } catch (Exception e) {
                        System.err.println("Failed to parse JSON content: " + content.toString());
                        throw new SecurityException("Error parsing decrypted configuration: " + e.getMessage());
                    }
                }

            } finally {
                // Clean up temporary files
                try {
                    new File(tempEncryptedFile).delete();
                    new File(tempDecryptedFile).delete();
                } catch (Exception e) {
                    System.err.println("Warning: Failed to clean up temporary files: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            if (e instanceof SecurityException) {
                throw e;
            }
            throw new SecurityException("Error during configuration fetch: " + e.getMessage());
        }

        return config;
    }

    /**
     * Fetches only public information about a car without requiring authentication.
     *
     * @param host  The target host address
     * @param port  The target port number
     * @param carId The identifier of the car to fetch information for
     * @return JsonObject containing the car's public information, or null if
     *         unavailable
     * @throws Exception If there are any communication issues
     */
    public JsonObject fetchPublicInfo(String host, int port, String carId) throws Exception {
        try (SSLSocket socket = createSSLSocket(host, port)) {
            socket.startHandshake();

            String fetchRequest = "FETCH_PUBLIC:" + carId;

            OutputStream os = socket.getOutputStream();
            os.write(fetchRequest.getBytes());
            os.flush();

            InputStream is = socket.getInputStream();
            byte[] data = new byte[8192];
            int len = is.read(data);

            if (len <= 0) {
                return null;
            }

            String response = new String(data, 0, len);

            try {
                JsonObject publicInfo = JsonParser.parseString(response).getAsJsonObject();
                this.lastFetchedConfig = publicInfo;
                return publicInfo;
            } catch (Exception e) {
                System.err.println("Error parsing public information: " + e.getMessage());
                System.err.println("Response was: " + response);
                return null;
            }
        } catch (Exception e) {
            System.err.println("Error fetching public information: " + e.getMessage());
            return null;
        }
    }

    /**
     * Sends a secure message containing configuration data to the server.
     * The message is encrypted and signed before transmission.
     *
     * @param host                 The target host address
     * @param port                 The target port number
     * @param inputFile            Path to the JSON configuration file to send
     * @param senderEcPrivateKey   The sender's EC private key for signing
     * @param receiverRsaPublicKey The receiver's RSA public key for encryption
     * @throws Exception         If there are any IO, security, or communication
     *                           issues
     * @throws SecurityException If the user ID in the configuration doesn't match
     *                           the sender
     */
    public void sendSecureMessage(String host, int port, String inputFile,
            PrivateKey senderEcPrivateKey,
            PublicKey receiverRsaPublicKey) throws Exception {

        // Read and parse the input configuration
        JsonObject config;
        try (FileReader reader = new FileReader(inputFile)) {
            config = gson.fromJson(reader, JsonObject.class);
        }

        // Verify the user ID in configuration matches the sender
        String configUserId = config.get("user").getAsString();
        if (!configUserId.equals(this.userId)) {
            throw new SecurityException("Cannot send configuration for user " + configUserId +
                    ". You are authenticated as " + this.userId);
        }

        // Create temporary files for processing
        String tempInputFile = "temp_input_" + System.currentTimeMillis() + ".json";
        String outputFile = "secure_message.json";

        try {
            // Write configuration to temporary file
            try (FileWriter writer = new FileWriter(tempInputFile)) {
                gson.toJson(config, writer);
            }

            // Encrypt and sign the message
            Protect.protect(tempInputFile, outputFile, senderEcPrivateKey, receiverRsaPublicKey);

            // Read the secure message for transmission
            String secureMessageJson;
            try (BufferedReader reader = new BufferedReader(new FileReader(outputFile))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                secureMessageJson = sb.toString();
            }

            // Send the secure message over SSL
            try (SSLSocket socket = createSSLSocket(host, port)) {
                socket.startHandshake();
                System.out.println("TLS handshake successful, sending secure message...");

                OutputStream os = socket.getOutputStream();
                os.write(secureMessageJson.getBytes());
                os.flush();
                System.out.println("Secure message sent to the server.");

                // Get and process the response
                InputStream is = socket.getInputStream();
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len > 0) {
                    System.out.printf("Response from Car: %s%n", new String(data, 0, len));
                }
            }
        } finally {
            // Clean up temporary files
            try {
                new File(tempInputFile).delete();
                new File(outputFile).delete();
            } catch (Exception e) {
                System.err.println("Warning: Failed to clean up temporary files: " + e.getMessage());
            }
        }
    }

    /**
     * Retrieves public car information from the last fetched configuration.
     * This method is safe to call without authentication as it only accesses public
     * data.
     *
     * @return JSON string containing public car information, or null if no
     *         configuration
     *         has been fetched or if public_car_info is not present in the
     *         configuration
     */
    public String getPublicCarInfo() {
        if (lastFetchedConfig == null) {
            return null;
        }
        // The configuration should always have public_car_info even if user doesn't own
        // it
        if (lastFetchedConfig.has("public_car_info")) {
            return gson.toJson(lastFetchedConfig.get("public_car_info"));
        }
        return null;
    }

    /**
     * Retrieves a specific configuration value from the private configuration
     * section.
     * This method uses a category-key structure to access nested configuration
     * values.
     *
     * @param category The top-level category in the configuration (e.g., "ac",
     *                 "seat")
     * @param key      The specific key within the category to retrieve
     * @return The string value associated with the key, or null if:
     *         - No configuration has been fetched
     *         - Private configuration section is missing
     *         - Category doesn't exist
     *         - Key is not found in the category
     */
    public String getConfigValue(String category, String key) {
        // Check if we have a valid configuration with private section
        if (lastFetchedConfig == null || !lastFetchedConfig.has("private_configuration")) {
            return null;
        }

        JsonObject config = lastFetchedConfig.getAsJsonObject("private_configuration");
        if (config.has(category)) {
            // Process the category array to find matching key
            // Using Java streams for efficient filtering and mapping
            return config.getAsJsonArray(category)
                    .asList()
                    .stream()
                    .map(element -> element.getAsJsonObject())
                    .filter(obj -> obj.keySet().contains(key))
                    .findFirst()
                    .map(obj -> obj.get(key).getAsString())
                    .orElse(null);
        }
        return null;
        }



    public static void giveKey(String host, int port, String userKeyPath, PrivateKey senderEcPrivateKey, PublicKey receiverRsaPublicKey) {
        String tempInputFile = "temp_input_" + System.currentTimeMillis() + ".json";

        try {
            // Write userKeyPath as JSON into the temporary file
            String jsonToWrite = new Gson().toJson(Collections.singletonMap("userKeyPath", userKeyPath));
            try (FileWriter writer = new FileWriter(tempInputFile)) {
                writer.write(jsonToWrite);
            }

            // Encrypt the JSON content using the receiver's RSA public key
            String encryptedMessage;
            try (BufferedReader reader = new BufferedReader(new FileReader(tempInputFile))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                String message = sb.toString();

                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, receiverRsaPublicKey);
                byte[] encryptedBytes = cipher.doFinal(message.getBytes());
                encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
            }

            // Create a secure message with encryption and signature
            String secureMessageJson = new Gson().toJson(Map.of(
                "encryptedMessage", encryptedMessage
            ));

            // Add USER_PRIVATE_KEY wrapper
            secureMessageJson = "{\"USER_PRIVATE_KEY\":" + secureMessageJson + "}";

            // Send the secure message over SSL
            try (SSLSocket socket = createSSLSocket(host, port)) {
                socket.startHandshake();
                System.out.println("TLS handshake successful, sending secure message...");

                OutputStream os = socket.getOutputStream();
                os.write(secureMessageJson.getBytes());
                os.flush();
                System.out.println("Secure message sent to the server.");

                // Receive and process the response
                InputStream is = socket.getInputStream();
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len > 0) {
                    System.out.printf("Response from server: %s%n", new String(data, 0, len));
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up temporary files
            try {
                new File(tempInputFile).delete();
            } catch (Exception e) {
                System.err.println("Failed to clean up temporary file: " + e.getMessage());
            }
        }
    }


    /**
     * Main method demonstrating the usage of secure configuration management.
     * Shows examples of sending and fetching configuration using asymmetric
     * encryption.
     *
     * @param args Command line arguments (not used)
     * @throws Exception If there are issues loading keys or performing
     *                   cryptographic operations
     */
    public static void main(String[] args) throws Exception {
        // Create a user instance
        User user = new User("user1");

        // Load the encryption keys for sending configuration
        // EC private key for signing, RSA public key for encryption
        PrivateKey senderEcPrivateKey = KeyLoader.loadECPrivateKey(
                "src/main/resources/keys/owner_ec_private_pkcs8.pem");
        PublicKey receiverRsaPublicKey = KeyLoader.loadRSAPublicKey(
                "src/main/resources/keys/car_rsa_public.pem");

        // Example of sending a new configuration
        String inputFile = "src/main/resources/input_config.json";
        user.sendSecureMessage("vm2", 5000, inputFile, senderEcPrivateKey, receiverRsaPublicKey);

        // Load the keys for fetching configuration
        // RSA private key for decryption, EC public key for verification
        PrivateKey userRsaPrivateKey = KeyLoader.loadRSAPrivateKey(
                "src/main/resources/keys/owner_rsa_private_pkcs8.pem");
        PublicKey carEcPublicKey = KeyLoader.loadECPublicKey(
                "src/main/resources/keys/car_ec_public.pem");

        // Example of fetching and using configuration
        JsonObject config = user.fetchConfiguration("localhost", 5000, "1234XYZ",
                userRsaPrivateKey, carEcPublicKey);

        if (config != null) {
            // Example of getting specific configuration values
            String acOut1 = user.getConfigValue("ac", "out1");
            String seatPos1 = user.getConfigValue("seat", "pos1");

            System.out.println("Fetched configuration:");
            System.out.println("AC Out1: " + acOut1);
            System.out.println("Seat Position 1: " + seatPos1);
        }
    }
}