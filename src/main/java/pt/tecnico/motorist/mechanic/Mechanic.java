package pt.tecnico.motorist.mechanic;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.security.InvalidKeyException;

import pt.tecnico.motorist.Unprotect;
import pt.tecnico.motorist.Check;
import pt.tecnico.motorist.KeyLoader;


/**
 * Class that represents a mechanic in the secure configuration management
 * system. The mechanic can fetch car configurations securely if he as the user autorisation
 * using asymmetric encryption and digital signatures.
 */
public class Mechanic {
    private String MechanicId;
    private static String pathcurrentKeyUser;

    /**
     * Constructs a new mechanic instance with the specified mechanic ID.
     *
     * @param MechanicId The unique identifier for the mechanic
     */
    public Mechanic(String MechanicId) {
        this.MechanicId = MechanicId;
    }

    /**
     * Retrieves the mechanic's ID.
     *
     * @return The mechanic's ID string
     */
    public String getMechanicId() {
        return this.MechanicId;
    }

        /**
     * Creates an SSL socket for secure communication with the specified host.
     * 
     * @param host The target host to connect to
     * @param port The port number to connect to
     * @return An initialized SSLSocket configured with TLS 1.3
     * @throws Exception If SSL configuration or connection fails
     */
    public static SSLSocket createSSLSocket(String host, int port) throws Exception {
        // Load client keystore with credentials
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/user.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        // Load client truststore for verifying server certificates
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/usertruststore.jks")) {
            trustStore.load(trustStoreIS, "changeme".toCharArray());
        }

        // Initialize key management factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeme".toCharArray());

        // Initialize trust management factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create and configure SSL context
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setEnabledProtocols(new String[] { "TLSv1.3" });

        return socket;
    }

    /**
     * Creates an SSL server socket for accepting secure connections.
     * 
     * @param port Port number to listen on
     * @return Configured SSLServerSocket
     * @throws Exception If server socket creation or SSL configuration fails
     */
    public static SSLServerSocket createSSLServerSocket(int port) throws Exception {
        // Load server credentials
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/mechanic.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        // Load trusted certificates for client authentication
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/mechanictruststore.jks")) {
            trustStore.load(trustStoreIS, "changeme".toCharArray());
        }

        // Initialize key and trust management
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeme".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create and configure SSL context
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

        // Enable mutual TLS authentication
        sslServerSocket.setNeedClientAuth(true);

        return sslServerSocket;
    }
   
    /**
     * Starts a secure server that listens for incoming connections from users.
     * 
     * @param port          Port number to listen on
     * @param host          Host address to bind to
     * @param userPublicKey Public key used to verify user signatures
     * @throws Exception If server setup or message processing fails
     */
    public static void startServer(int port, String host, PublicKey userPublicKey) throws Exception {
        try (SSLServerSocket listener = createSSLServerSocket(port)) {
            System.out.println("Mechanic is running. Waiting for user connection ...");

            try (Socket socket = listener.accept()) {
                System.out.println("Connection established with client.");

                // Read incoming message
                InputStream is = socket.getInputStream();
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len == -1) {
                    System.out.println("No data received. Closing connection.");
                    return;
                }

                String secureMessageJson = new String(data, 0, len);
                System.out.println("Received secure message: " + secureMessageJson);

                // Process message and send response
                processMessage(secureMessageJson, "temp_secure_message.json", userPublicKey, socket.getOutputStream());
            } catch (Exception e) {
                System.err.println("Error processing message: " + e.getMessage());
                e.printStackTrace();
            }

            System.out.println("Processing complete. Shutting down server.");
        }
    }

    /**
     * Helper method to send error responses.
     * 
     * @param os      Output stream to write the response to
     * @param message Error message to include in the response
     * @throws IOException If writing to the output stream fails
     */
    private static void sendErrorResponse(OutputStream os, String message) throws IOException {
        JsonObject errorResponse = new JsonObject();
        errorResponse.addProperty("status", "error");
        errorResponse.addProperty("message", message);
        os.write(errorResponse.toString().getBytes());
        os.flush();
    }

    /**
     * Processes incoming messages and handles different message types
     * appropriately.
     * 
     * @param messageJson           JSON string containing the message to process
     * @param inputFile             Input file path (if needed for processing)
     * @param manufacturerPublicKey Public key used to verify manufacturer
     *                              signatures
     * @param os                    Output stream for sending responses
    * @throws Exception If message processing fails
    */
    public static void processMessage(String messageJson, String inputFile, PublicKey manufacturerPublicKey, OutputStream os) throws Exception {
        // Load the private key for the mechanic
        PrivateKey mechanicPrivateKey = KeyLoader.loadRSAPrivateKey("src/main/resources/keys/mechanic.key");

        try {
            // Parse the JSON message
            JsonObject message = JsonParser.parseString(messageJson).getAsJsonObject();

            if (message.has("USER_PRIVATE_KEY")) {
                JsonObject secureMessage = message.getAsJsonObject("USER_PRIVATE_KEY");

                if (!secureMessage.has("encryptedMessage")) {
                    sendErrorResponse(os, "Invalid message format: Missing required fields");
                    return;
                }

                // Extract the encrypted message
                String encryptedMessage = secureMessage.get("encryptedMessage").getAsString();

                // Decrypt the message
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, mechanicPrivateKey);
                byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
                byte[] decryptedBytes = cipher.doFinal(encryptedMessageBytes);

                // Convert decrypted bytes to a string
                String decryptedMessage = new String(decryptedBytes);
                System.out.println("Decrypted Message: " + decryptedMessage);

                // Extract the path from the decrypted message
                String pathToKey;
                if (decryptedMessage.startsWith("{")) {
                    // If the decrypted message is JSON, parse it to extract the path
                    JsonObject decryptedJson = JsonParser.parseString(decryptedMessage).getAsJsonObject();
                    if (decryptedJson.has("userKeyPath")) {
                        pathToKey = decryptedJson.get("userKeyPath").getAsString();
                    } else {
                        sendErrorResponse(os, "Decrypted message does not contain 'path' field");
                        return;
                    }
                } else {
                    // If it's plain text, use it directly as the path
                    pathToKey = decryptedMessage.trim();
                }

                // Handle the extracted path
                System.out.println("Extracted Path: " + pathToKey);
                pathcurrentKeyUser = pathToKey;

            } else {
                sendErrorResponse(os, "Unsupported message");
            }

            os.flush();
        } catch (Exception e) {
            sendErrorResponse(os, "Error processing message: " + e.getMessage());
            throw e;
        }
    }


    /**
     * Fetch a car configuration using secure communication.
     * 
     * @param host          The target host to connect to
     * @param port          The port number to connect to
     * @param carId         The unique identifier for the car
     * @param configuration The configuration data to send
     * @param carPublicKey  The public key of the car for encryption
     * @throws Exception If there are issues with SSL communication or
     *                   cryptographic operations
     */
    public JsonObject fetchConfiguration(String host, int port, String userId , String carId,
            PublicKey carEcPublicKey, boolean publicOnly) throws Exception {
        JsonObject config = null;

        if (!pathcurrentKeyUser.isEmpty()){
            PrivateKey userRsaPrivateKey = KeyLoader.loadRSAPrivateKey(pathcurrentKeyUser);
            
            try (SSLSocket socket = createSSLSocket(host, port)) {
                socket.startHandshake();

                // Prepare the fetch request based on access type
                String fetchRequest = publicOnly ? "FETCH_PUBLIC:" + carId + ":" + userId
                        : "FETCH:" + carId + ":" + userId;

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
                            // this.lastFetchedConfig = config;
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
        }else {
            System.out.print("You need to have a private user private key to see the user configuration");
        }

        return config;
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
        Mechanic mechanic = new Mechanic("mechanic1");

        // Load the encryption keys for sending configuration
        // EC private key for signing, RSA public key for encryption
        PrivateKey senderEcPrivateKey = KeyLoader.loadECPrivateKey(
                "src/main/resources/keys/owner_ec_private_pkcs8.pem");
        PublicKey receiverRsaPublicKey = KeyLoader.loadRSAPublicKey(
                "src/main/resources/keys/car_rsa_public.pem");


    }
}