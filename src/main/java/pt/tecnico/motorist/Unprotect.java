package pt.tecnico.motorist;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.FileWriter;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Unprotect {
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final Duration FRESHNESS_WINDOW = Duration.ofMinutes(5);
    private static final Set<String> usedNonces = new HashSet<>();
    private static boolean isDbFetch = false;  // New flag for database fetches

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // New method to set database fetch mode
    public static void setDatabaseFetchMode(boolean isDatabaseFetch) {
        isDbFetch = isDatabaseFetch;
    }

    public static void unprotect(String inputFile, String outputFile, PrivateKey receiverPrivateKey) throws Exception {
        // Read the secure message
        Gson gson = new Gson();
        JsonObject secureMessage;
        try (FileReader reader = new FileReader(inputFile)) {
            secureMessage = gson.fromJson(reader, JsonObject.class);
        }

        // Extract components
        byte[] cipherText = Base64.getDecoder().decode(secureMessage.get("cipherText").getAsString());
        byte[] encryptedAesKey = Base64.getDecoder().decode(secureMessage.get("encryptedAesKey").getAsString());
        byte[] iv = Base64.getDecoder().decode(secureMessage.get("iv").getAsString());

        // Decrypt the AES key using receiver's private key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.UNWRAP_MODE, receiverPrivateKey);
        Key aesKey = rsaCipher.unwrap(encryptedAesKey, "AES", Cipher.SECRET_KEY);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        // Decrypt the document
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, (SecretKey) aesKey, gcmSpec);
        byte[] plainBytes = aesCipher.doFinal(cipherText);
        String plainText = new String(plainBytes, "UTF-8");

        // Parse the decrypted JSON
        JsonObject plainObject = gson.fromJson(plainText, JsonObject.class);

        // Only perform freshness checks if not fetching from database
        if (!isDbFetch) {
            // Verify nonce
            String nonce = plainObject.get("nonce").getAsString();
            if (usedNonces.contains(nonce)) {
                throw new SecurityException("Replay attack detected! Nonce already used.");
            }
            usedNonces.add(nonce);

            // Verify timestamp freshness
            String timestampStr = plainObject.get("timestamp").getAsString();
            Instant timestamp = Instant.parse(timestampStr);
            if (Duration.between(timestamp, Instant.now()).abs().compareTo(FRESHNESS_WINDOW) > 0) {
                throw new SecurityException("Document freshness failed! Timestamp is invalid.");
            }
        }

        // Remove nonce and timestamp before saving
        plainObject.remove("nonce");
        plainObject.remove("timestamp");

        // Write the decrypted document to the output file
        try (FileWriter writer = new FileWriter(outputFile)) {
            gson.toJson(plainObject, writer);
        }

        System.out.println("Document unprotected and saved to " + outputFile);
    }

    /**
     * Main method for standalone execution.
     * Usage: java Unprotect <inputFile> <outputFile> <receiverPrivateKeyFile>
     */
    public static void main(String[] args) {
        try {
            // Check arguments
            if (args.length != 3) {
                System.err.println("Usage: java unprotect <inputFile> <outputFile> <receiverPrivateKeyFile>");
                System.exit(1);
            }

            String inputFile = args[0];
            String outputFile = args[1];
            String receiverPrivateKeyFile = args[2];

            // Load receiver's private key
            PrivateKey receiverPrivateKey = KeyLoader.loadRSAPrivateKey(receiverPrivateKeyFile);

            // Call unprotect method
            unprotect(inputFile, outputFile, receiverPrivateKey);

        } catch (Exception e) {
            System.err.println("An error occurred during the unprotect process:");
            e.printStackTrace();
            System.exit(1);
        }
    }
}