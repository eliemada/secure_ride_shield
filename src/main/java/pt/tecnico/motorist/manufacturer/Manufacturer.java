package pt.tecnico.motorist.manufacturer;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import pt.tecnico.motorist.FirmwareCrypto;
import pt.tecnico.motorist.KeyLoader;

/**
 * Manufacturer class that retrieves firmware updates from the manufacturer's server and sends them to cars.
 */
public class Manufacturer {

    private String manufacturerId;
    private static final Gson gson = new Gson(); // Add this line to initialize Gson

    public Manufacturer(String manufacturerId) {
        this.manufacturerId = manufacturerId;
    }

    /**
     * Create an SSL socket with the given host and port.
     * @param host the host name
     * @param port the port number
     * @return the created SSL socket
     * @throws Exception if an error occurs
     */
    public static SSLSocket createSSLSocket(String host, int port) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreIS = new FileInputStream("src/main/resources/keys/manufacturer.p12")) {
            keyStore.load(keyStoreIS, "changeme".toCharArray());
        }

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("src/main/resources/keys/manufacturertruststore.jks")) {
            trustStore.load(trustStoreIS, "changeme".toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeme".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();
        return (SSLSocket) factory.createSocket(host, port);
    }

    /**
     * Retrieve a firmware update from the manufacturer's server.
     * @param firmwareID the ID of the firmware to retrieve
     * @return the firmware update
     * @throws Exception if an error occurs
     */
    public String retrieveFirmwareUpdate(String firmwareID) throws Exception {
        try (SSLSocket socket = createSSLSocket("vm2", 5000)) {
            socket.startHandshake();

            // Create JSON request
            JsonObject requestJson = new JsonObject();
            requestJson.addProperty("type", "FETCH_FIRMWARE");
            requestJson.addProperty("firmwareID", firmwareID);
            requestJson.addProperty("sender", manufacturerId);

            // Send firmware retrieval request
            OutputStream os = socket.getOutputStream();
            os.write(requestJson.toString().getBytes());
            os.flush();

            // Receive response from the server
            InputStream is = socket.getInputStream();
            byte[] data = new byte[8192];
            int len = is.read(data);
            if (len <= 0) {
                throw new IOException("No response received from the server.");
            }

            String response = new String(data, 0, len);
            System.out.println("Raw response: " + response); // Debug print

            JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();

            if (responseJson.has("status") && "error".equals(responseJson.get("status").getAsString())) {
                throw new Exception(responseJson.get("message").getAsString());
            }

            // Extract the firmware from the response
            String firmware = responseJson.get("firmware").getAsString();
            System.out.println("Extracted firmware: " + firmware); // Debug print
            return firmware;
        }
    }

    /**
     * Send a firmware update to a car.
     * @param firmwareUpdate the firmware update to send
     * @param manufacturerPrivateKey the manufacturer's private key
     * @param carPublicKey the car's public key
     * @param host the host name of the car
     * @param port the port number of the car
     * @throws Exception if an error occurs
     */
    public void sendFirmwareToCar(String firmwareUpdate, PrivateKey manufacturerPrivateKey, PublicKey carPublicKey, String host, int port)
            throws Exception {
        // Protect the firmware using FirmwareCrypto
        String protectedFirmware = FirmwareCrypto.protect(firmwareUpdate, manufacturerPrivateKey, carPublicKey);

        // Create the webserver message
        JsonObject message = new JsonObject();
        message.addProperty("type", "FIRMWARE_UPDATE");
        message.addProperty("sender", manufacturerId);  // Add sender ID
        message.addProperty("firmware", protectedFirmware);

        // Send to webserver
        try (SSLSocket socket = createSSLSocket(host, port)) {
            socket.startHandshake();

            OutputStream os = socket.getOutputStream();
            os.write(gson.toJson(message).getBytes());
            os.flush();

            System.out.println("Protected firmware update sent to the car.");

            // Receive acknowledgment
            InputStream is = socket.getInputStream();
            byte[] data = new byte[2048];
            int len = is.read(data);
            if (len > 0) {
                System.out.printf("Response from Car: %s%n", new String(data, 0, len));
            }
        }
    }

    /**
     * Main method to test the Manufacturer class.
     * @param args the command-line arguments
     * @throws Exception if an error occurs
     */
    public static void main(String[] args) throws Exception {
        Manufacturer manufacturer = new Manufacturer("manufacturer");

        // Load keys for signing and encryption
        PrivateKey manufacturerPrivateKey = KeyLoader.loadECPrivateKey(
                "src/main/resources/keys/manufacturer_ec_private_pkcs8.pem");
        PublicKey carPublicKey = KeyLoader.loadRSAPublicKey(
                "src/main/resources/keys/car_rsa_public.pem");

        // Example usage: Retrieve and send firmware update
        String firmwareID = "firmware123";
        try {
            System.out.println("Retrieving firmware update...");
            String firmwareUpdate = manufacturer.retrieveFirmwareUpdate(firmwareID);

            System.out.println("Sending firmware update to car...");
            manufacturer.sendFirmwareToCar(firmwareUpdate, manufacturerPrivateKey, carPublicKey, "localhost", 5001);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
