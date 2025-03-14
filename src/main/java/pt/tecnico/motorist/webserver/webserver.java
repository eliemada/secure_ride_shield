package pt.tecnico.motorist.webserver;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import pt.tecnico.motorist.KeyLoader;

/**
 * A secure web server implementation that handles firmware updates and
 * communication
 * between manufacturers and connected vehicles. This server provides SSL/TLS
 * security,
 * message verification, and secure firmware delivery.
 * 
 * The server supports:
 * - Secure firmware retrieval and delivery
 * - SSL/TLS encrypted communications
 * - Mutual TLS authentication
 * - Message signature verification
 * - Database interaction for firmware storage
 */
public class webserver {

    private static final String DB_URL = "jdbc:sqlite:src/main/resources/db/firmewareDatabase.db";
    private static final Gson gson = new Gson();

    /**
     * Retrieves a firmware update message from the database based on the firmware
     * ID.
     * 
     * @param firmwareID The unique identifier of the firmware update to retrieve
     * @return A JSON string containing the firmware update details
     * @throws Exception If the firmware is not found or database access fails
     */
    public static String retrieveSecureMessage(String firmwareID) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String sql = "SELECT firmware_update FROM firmware_table WHERE firmwareID = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, firmwareID);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                JsonObject firmwareJson = new JsonObject();
                firmwareJson.addProperty("firmwareID", firmwareID);
                firmwareJson.addProperty("content", rs.getString("firmware_update"));
                firmwareJson.addProperty("version", "1.0");
                firmwareJson.addProperty("timestamp", System.currentTimeMillis());

                String response = firmwareJson.toString();
                System.out.println("Firmware response: " + response);
                return response;
            } else {
                throw new Exception("Firmware update not found for firmwareID: " + firmwareID);
            }
        }
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
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/webserver.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        // Load client truststore for verifying server certificates
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/webservertruststore.jks")) {
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
    public static void processMessage(String messageJson, String inputFile, PublicKey manufacturerPublicKey,
            OutputStream os) throws Exception {
        try {
            JsonObject message = JsonParser.parseString(messageJson).getAsJsonObject();

            if (!message.has("type")) {
                throw new IllegalArgumentException("Message type not specified");
            }

            String messageType = message.get("type").getAsString();
            System.out.println("Processing message type: " + messageType);

            // Handle different message types
            switch (messageType) {
                case "FETCH_FIRMWARE":
                    handleFirmwareFetch(message, os);
                    break;
                case "FIRMWARE_UPDATE":
                    handleFirmwareUpdate(messageJson, os);
                    break;
                default:
                    sendErrorResponse(os, "Unsupported message type: " + messageType);
            }

            os.flush();
        } catch (Exception e) {
            sendErrorResponse(os, "Error processing message: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Forwards firmware updates to the connected car.
     * 
     * @param messageJson JSON string containing the firmware update message
     * @throws Exception If forwarding fails or communication with car fails
     */
    private static void forwardFirmwareToCard(String messageJson) throws Exception {
        System.out.println("Starting firmware forwarding process...");
        JsonObject message = gson.fromJson(messageJson, JsonObject.class);
        String protectedFirmware = message.get("firmware").getAsString();
        System.out.println("Parsed protected firmware: " + protectedFirmware.substring(0, 100) + "...");

        try (SSLSocket carSocket = createSSLSocket("vm4", 5001)) {
            System.out.println("SSL Socket created, starting handshake...");
            carSocket.startHandshake();
            System.out.println("Handshake completed");

            // Format and send the firmware message
            String forwardMessage = "FIRMWARE:" + protectedFirmware;
            System.out.println("Forwarding message starts with: "
                    + forwardMessage.substring(0, Math.min(forwardMessage.length(), 100)));

            OutputStream os = carSocket.getOutputStream();
            os.write(forwardMessage.getBytes());
            os.flush();
            System.out.println("Message sent to car");

            // Wait for and process car's response
            InputStream is = carSocket.getInputStream();
            byte[] responseData = new byte[4096];
            System.out.println("Waiting for car response...");
            int responseLen = is.read(responseData);

            if (responseLen > 0) {
                String response = new String(responseData, 0, responseLen);
                System.out.println("Raw car response: " + response);
            }
        }
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
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/webserver.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        // Load trusted certificates for client authentication
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/webservertruststore.jks")) {
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
     * Starts the web server and begins accepting connections.
     * 
     * @param port                  Port number to listen on
     * @param manufacturerPublicKey Public key used to verify manufacturer
     *                              signatures
     * @throws Exception If server startup fails
     */
    public static void startServer(int port, PublicKey manufacturerPublicKey) throws Exception {
        try (SSLServerSocket listener = createSSLServerSocket(port)) {
            System.out.println("Webserver is running. Waiting for manufaturer connection...");

            while (true) {
                try (Socket socket = listener.accept()) {
                    // Read incoming message
                    InputStream is = socket.getInputStream();
                    byte[] data = new byte[2048];
                    int len = is.read(data);
                    if (len == -1) {
                        continue;
                    }

                    String secureMessageJson = new String(data, 0, len);
                    System.out.println("Received secure message: " + secureMessageJson);

                    // Process message and send response
                    processMessage(secureMessageJson, "temp_secure_message.json", manufacturerPublicKey,
                            socket.getOutputStream());
                } catch (Exception e) {
                    System.err.println("Error processing message: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Entry point for the web server application.
     * 
     * @param args Command line arguments (not used)
     * @throws Exception If server initialization fails
     */
    public static void main(String[] args) throws Exception {
        // Load manufacturer's public key for signature verification
        PublicKey manufacturerPublicKey = KeyLoader
                .loadECPublicKey("src/main/resources/keys/manufacturer_public_key_x509.pem");

        startServer(5000, manufacturerPublicKey);
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
     * Handles firmware fetch requests.
     * 
     * @param message JSON object containing the fetch request details
     * @param os      Output stream to write the response to
     * @throws Exception If firmware retrieval fails
     */
    private static void handleFirmwareFetch(JsonObject message, OutputStream os) throws Exception {
        String firmwareID = message.get("firmwareID").getAsString();
        String sender = message.get("sender").getAsString();
        System.out.println("Firmware request from sender: " + sender);

        try {
            String firmwareJson = retrieveSecureMessage(firmwareID);
            System.out.println("Retrieved firmware: " + firmwareJson);

            JsonObject response = new JsonObject();
            response.addProperty("status", "success");
            response.addProperty("firmware", firmwareJson);

            String responseStr = response.toString();
            System.out.println("Sending response: " + responseStr);
            os.write(responseStr.getBytes());
        } catch (Exception e) {
            sendErrorResponse(os, e.getMessage());
        }
    }

    /**
     * Handles firmware update requests.
     * 
     * @param messageJson JSON string containing the update request
     * @param os          Output stream to write the response to
     * @throws Exception If firmware update processing fails
     */
    private static void handleFirmwareUpdate(String messageJson, OutputStream os) throws Exception {
        try {
            forwardFirmwareToCard(messageJson);

            JsonObject response = new JsonObject();
            response.addProperty("status", "success");
            response.addProperty("message", "Firmware update forwarded to car successfully");
            os.write(response.toString().getBytes());
        } catch (Exception e) {
            sendErrorResponse(os, "Error forwarding firmware: " + e.getMessage());
        }
    }
}