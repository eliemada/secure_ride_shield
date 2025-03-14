package pt.tecnico.motorist;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.FileWriter;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Protect {
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String ECDSA_ALGORITHM = "SHA3-256withECDSA";
    private static final int GCM_TAG_LENGTH = 128; // in bits

    public static void protect(String inputFile, String outputFile, PrivateKey senderPrivateKey,
            PublicKey receiverPublicKey) throws Exception {
        Gson gson = new Gson();
        JsonObject plainObject;
        try (FileReader reader = new FileReader(inputFile)) {
            plainObject = gson.fromJson(reader, JsonObject.class);
        }

        String senderID = plainObject.get("user").getAsString(); // Extracting "user" as senderID
        String receiverID = plainObject.get("carID").getAsString(); // Extracting "carID" as receiverID

        // Create protected version of the configuration
        JsonObject protectedConfig = new JsonObject();
        protectedConfig.addProperty("carID", receiverID);
        protectedConfig.addProperty("user", senderID);

        // Include private configuration if present
        if (plainObject.has("private_configuration")) {
            protectedConfig.add("private_configuration", plainObject.getAsJsonObject("private_configuration"));
        }

        // Include public car info if present
        if (plainObject.has("public_car_info")) {
            protectedConfig.add("public_car_info", plainObject.getAsJsonObject("public_car_info"));
        }

        // Add nonce and timestamp
        protectedConfig.addProperty("nonce", UUID.randomUUID().toString());
        protectedConfig.addProperty("timestamp", Instant.now().toString());

        // Serialize the updated JSON
        String plainText = gson.toJson(protectedConfig);
        byte[] plainBytes = plainText.getBytes("UTF-8");

        // Generate AES key and IV
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[12]; // 96 bits for GCM
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Encrypt the document
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] cipherText = aesCipher.doFinal(plainBytes);

        // Encrypt the AES key with the receiver's public key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, receiverPublicKey);
        byte[] encryptedAesKey = rsaCipher.wrap(aesKey);

        // Hash the cipherText using SHA3-256
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(cipherText);

        // Sign the hash using ECDSA
        Signature ecdsaSign = Signature.getInstance(ECDSA_ALGORITHM, "BC");
        ecdsaSign.initSign(senderPrivateKey);
        ecdsaSign.update(hash);
        byte[] signature = ecdsaSign.sign();

        // Assemble the secure message
        JsonObject secureMessage = new JsonObject();
        secureMessage.addProperty("cipherText", Base64.getEncoder().encodeToString(cipherText));
        secureMessage.addProperty("encryptedAesKey", Base64.getEncoder().encodeToString(encryptedAesKey));
        secureMessage.addProperty("iv", Base64.getEncoder().encodeToString(iv));
        secureMessage.addProperty("signature", Base64.getEncoder().encodeToString(signature));
        secureMessage.addProperty("sender", senderID);
        secureMessage.addProperty("receiver", receiverID);

        // Write the secure message to the output file
        try (FileWriter writer = new FileWriter(outputFile)) {
            gson.toJson(secureMessage, writer);
        }

        System.out.println("Document protected and saved to " + outputFile);
    }

    /**
     * Main method for standalone execution.
     * Usage: java Protect <inputFile> <outputFile> <senderPrivateKeyFile>
     * <receiverPublicKeyFile>
     */
    public static void main(String[] args) {
        try {
            // Register Bouncy Castle as a security provider
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }

            // Check arguments
            if (args.length != 4) {
                System.err.println(
                        "Usage: java Protect <inputFile> <outputFile> <senderPrivateKeyFile> <receiverPublicKeyFile>");
                System.exit(1);
            }

            String inputFile = args[0];
            String outputFile = args[1];
            String senderPrivateKeyFile = args[2];
            String receiverPublicKeyFile = args[3];

            // Load keys
            PrivateKey senderPrivateKey = KeyLoader.loadECPrivateKey(senderPrivateKeyFile);
            PublicKey receiverPublicKey = KeyLoader.loadRSAPublicKey(receiverPublicKeyFile);

            // Call protect method
            protect(inputFile, outputFile, senderPrivateKey, receiverPublicKey);

        } catch (Exception e) {
            System.err.println("An error occurred during the protect process:");
            e.printStackTrace();
            System.exit(1);
        }
    }
}