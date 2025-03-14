package pt.tecnico.motorist;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.security.*;
import java.util.Base64;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Check {
    private static boolean isAuditMode = false;
    private static final String ECDSA_ALGORITHM = "SHA3-256withECDSA";
    private static final Gson gson = new Gson();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // Add setter for audit mode
    public static void setAuditMode(boolean isAudit) {
        isAuditMode = isAudit;
    }

    public static boolean check(String inputFile, PublicKey senderPublicKey) throws Exception {
        // Read the secure message from the input file
        JsonObject secureMessage;
        try (FileReader reader = new FileReader(inputFile)) {
            secureMessage = gson.fromJson(reader, JsonObject.class);
        }

        // Extract the cipherText and signature
        String cipherTextBase64 = secureMessage.get("cipherText").getAsString();
        String signatureBase64 = secureMessage.get("signature").getAsString();
        byte[] cipherText = Base64.getDecoder().decode(cipherTextBase64);
        byte[] signature = Base64.getDecoder().decode(signatureBase64);

        // Hash the cipherText using SHA3-256
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(cipherText);

        // Verify the signature using ECDSA with SHA3-256
        Signature ecdsaVerify = Signature.getInstance(ECDSA_ALGORITHM, "BC");
        ecdsaVerify.initVerify(senderPublicKey);
        ecdsaVerify.update(hash);
        boolean isSignatureValid = ecdsaVerify.verify(signature);

        // Only perform timestamp and nonce checks when NOT in audit mode
        if (isSignatureValid && !isAuditMode) {
            // Check timestamp freshness
            if (secureMessage.has("timestamp")) {
                long timestamp = Long.parseLong(secureMessage.get("timestamp").getAsString());
                long currentTime = System.currentTimeMillis();
                long timeDifference = currentTime - timestamp;

                // Define acceptable time window (e.g., 5 minutes)
                long timeWindow = 5 * 60 * 1000; // 5 minutes in milliseconds

                if (timeDifference > timeWindow) {
                    throw new SecurityException("Document freshness failed! Timestamp is invalid.");
                }
            }

            System.out.println("Signature is valid.");
        } else if (!isSignatureValid && !isAuditMode) {
            System.out.println("Signature verification failed!");
        }

        return isSignatureValid;
    }

    // Main method for standalone execution (optional)
    public static void main(String[] args) {
        try {
            // Register Bouncy Castle as a security provider
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }

            // Check arguments
            if (args.length != 2) {
                System.err.println("Usage: java Check <inputFile> <senderPublicKeyFile>");
                return;
            }

            String inputFile = args[0];
            String senderPublicKeyFile = args[1];

            // Load the sender's public key
            PublicKey senderPublicKey = KeyLoader.loadECPublicKey(senderPublicKeyFile);

            // Perform the check
            boolean result = check(inputFile, senderPublicKey);

            if (result) {
                System.out.println("The secure message has been verified successfully.");
            } else {
                System.out.println("The secure message verification failed.");
            }

        } catch (Exception e) {
            System.err.println("An error occurred during the verification process:");
            e.printStackTrace();
        }
    }

    public static boolean verifyStoredMessage(String originalMessage, String storedSignature, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {

            // Parse the message to get the cipherText
            JsonObject messageJson = gson.fromJson(originalMessage, JsonObject.class);
            String cipherTextBase64 = messageJson.get("cipherText").getAsString();
            byte[] cipherText = Base64.getDecoder().decode(cipherTextBase64);

            // Hash the cipherText using SHA3-256, just like in check()
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            byte[] hash = digest.digest(cipherText);

            // Verify using ECDSA with SHA3-256 and Bouncy Castle
            Signature ecdsaVerify = Signature.getInstance(ECDSA_ALGORITHM, "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(hash);

            // Decode and verify the signature
            byte[] signatureBytes = Base64.getDecoder().decode(storedSignature);

            boolean isValid = ecdsaVerify.verify(signatureBytes);
            System.out.println("Signature verification result: " + isValid);
            return isValid;

        } catch (Exception e) {
            System.err.println("Error in signature verification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
