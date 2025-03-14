package pt.tecnico.motorist;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.nio.charset.StandardCharsets;
import java.time.Duration; // For Duration
import java.util.Set; // For Set
import java.util.HashSet; // For HashSet
import java.util.Map;

public class AuditCrypto {
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String ECDSA_ALGORITHM = "SHA3-256withECDSA";
    private static final int GCM_TAG_LENGTH = 128;
    private static final Gson gson = new Gson();
    private static boolean isDbFetch = false;
    private static final Duration FRESHNESS_WINDOW = Duration.ofMinutes(5);
    private static final Set<String> usedNonces = new HashSet<>();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Protects an audit trail by encrypting and signing it.
     * 
     * @param auditTrail        JSON string containing the audit trail
     * @param auditorPrivateKey Private key of the auditor for signing
     * @param receiverPublicKey Public key of the receiver for encryption
     * @return Protected audit trail as JSON string
     */
    public static String protect(String auditTrail, PrivateKey auditorPrivateKey,
            PublicKey receiverPublicKey, long timestamp, String nonce) throws Exception {
        // Parse the audit JSON
        JsonObject auditObject = gson.fromJson(auditTrail, JsonObject.class);

        // Extract metadata for verification
        JsonObject metadata = auditObject.getAsJsonObject("audit_metadata");
        String carId = metadata.get("car_id").getAsString();
        String requestingUser = metadata.get("requesting_user").getAsString();

        // Convert audit to bytes for encryption
        byte[] plainBytes = auditTrail.getBytes(StandardCharsets.UTF_8);

        // Generate AES key for encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Generate IV for GCM mode
        byte[] iv = new byte[12];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Encrypt the audit trail
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] cipherText = aesCipher.doFinal(plainBytes);

        // Encrypt the AES key with receiver's public key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, receiverPublicKey);
        byte[] encryptedAesKey = rsaCipher.wrap(aesKey);

        // Hash and sign the cipherText
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(cipherText);

        Signature ecdsaSign = Signature.getInstance(ECDSA_ALGORITHM, "BC");
        ecdsaSign.initSign(auditorPrivateKey);
        ecdsaSign.update(hash);
        byte[] signature = ecdsaSign.sign();

        // Add timestamp and nonce to the protected audit
        if (timestamp == 0) {
            timestamp = System.currentTimeMillis();
        }
        if (nonce == null || nonce.isEmpty()) {
            nonce = java.util.UUID.randomUUID().toString();
        }

        // Create protected audit message
        JsonObject protectedAudit = new JsonObject();
        protectedAudit.addProperty("cipherText", Base64.getEncoder().encodeToString(cipherText));
        protectedAudit.addProperty("encryptedAesKey", Base64.getEncoder().encodeToString(encryptedAesKey));
        protectedAudit.addProperty("iv", Base64.getEncoder().encodeToString(iv));
        protectedAudit.addProperty("signature", Base64.getEncoder().encodeToString(signature));
        protectedAudit.addProperty("carId", carId);
        protectedAudit.addProperty("requestingUser", requestingUser);
        protectedAudit.addProperty("type", "AUDIT_TRAIL");
        protectedAudit.addProperty("timestamp", timestamp);
        protectedAudit.addProperty("nonce", nonce);

        return gson.toJson(protectedAudit);
    }

    /**
     * Unprotects an encrypted audit trail.
     * 
     * @param protectedAuditTrail Protected audit trail as JSON string
     * @param receiverPrivateKey  Private key of the receiver for decryption
     * @return Decrypted audit trail as JSON string
     */
    public static String unprotect(String protectedAuditTrail, PrivateKey receiverPrivateKey)
            throws Exception {
        // Parse the protected audit message
        JsonObject protectedAudit = gson.fromJson(protectedAuditTrail, JsonObject.class);

        // Extract components
        byte[] cipherText = Base64.getDecoder().decode(protectedAudit.get("cipherText").getAsString());
        byte[] encryptedAesKey = Base64.getDecoder().decode(protectedAudit.get("encryptedAesKey").getAsString());
        byte[] iv = Base64.getDecoder().decode(protectedAudit.get("iv").getAsString());

        // Decrypt the AES key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.UNWRAP_MODE, receiverPrivateKey);
        Key aesKey = rsaCipher.unwrap(encryptedAesKey, "AES", Cipher.SECRET_KEY);

        // Decrypt the audit trail
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, (SecretKey) aesKey, gcmSpec);
        byte[] plainBytes = aesCipher.doFinal(cipherText);

        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Checks the signature of a protected audit trail.
     * 
     * @param protectedAuditTrail Protected audit trail as JSON string
     * @param auditorPublicKey    Public key of the auditor for verification
     * @return true if signature is valid, false otherwise
     */
    public static boolean check(String protectedAuditTrail, PublicKey auditorPublicKey) throws Exception {
        // Parse the protected audit message
        JsonObject protectedAudit = gson.fromJson(protectedAuditTrail, JsonObject.class);

        // Extract components
        byte[] cipherText = Base64.getDecoder().decode(protectedAudit.get("cipherText").getAsString());
        byte[] signature = Base64.getDecoder().decode(protectedAudit.get("signature").getAsString());

        // Hash the cipherText
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(cipherText);

        // Verify signature
        Signature ecdsaVerify = Signature.getInstance(ECDSA_ALGORITHM, "BC");
        ecdsaVerify.initVerify(auditorPublicKey);
        ecdsaVerify.update(hash);

        return ecdsaVerify.verify(signature);
    }

    /**
     * Verifies the integrity of an audit trail.
     * 
     * @param auditTrail          Decrypted audit trail as JSON string
     * @param carId               Car ID to verify against
     * @param protectedAuditTrail Protected audit trail as JSON string for signature
     *                            verification
     * @param auditorPublicKey    Public key of the auditor for verification
     * @return true if audit trail is valid, false otherwise
     */
    public static boolean verifyAuditTrailIntegrity(String auditTrail, String carId,
            String protectedAuditTrail, PublicKey auditorPublicKey) throws Exception {

        JsonObject auditObject = gson.fromJson(auditTrail, JsonObject.class);

        // Verify metadata exists
        JsonObject metadata = auditObject.getAsJsonObject("audit_metadata");
        if (metadata == null) {
            System.out.println("ERROR: Missing audit_metadata");
            return false;
        }

        String actualCarId = metadata.get("car_id").getAsString();
        System.out.println("Actual Car ID: " + actualCarId);

        if (!actualCarId.equals(carId)) {
            System.out.println("ERROR: Car ID mismatch!");
            return false;
        }
        System.out.println("Car ID verification: PASSED");

        // Verify entries array exists
        JsonArray entries = auditObject.getAsJsonArray("audit_entries");
        if (entries == null) {
            System.out.println("ERROR: Missing audit_entries array");
            return false;
        }
        System.out.println("Found " + entries.size() + " audit entries");

        // Verify signature
        boolean signatureValid = check(protectedAuditTrail, auditorPublicKey);
        System.out.println("Signature verification: " + (signatureValid ? "PASSED" : "FAILED"));

        if (!signatureValid) {
            return false;
        }

        // Verify message numbers for CONFIG_UPDATE actions
        Map<String, Integer> lastMessageNumberPerUser = new HashMap<>();

        // Since entries are in reverse chronological order (newest first)
        // We expect message numbers to decrease as we go through the array
        for (int i = 0; i < entries.size(); i++) {
            JsonObject entry = entries.get(i).getAsJsonObject();
            String action = entry.get("action").getAsString();
            String user = entry.get("user").getAsString();

            if ("CONFIG_UPDATE".equals(action)) {
                int currentMessageNumber = entry.get("message_number").getAsInt();
                String timestamp = entry.get("timestamp").getAsString();
                System.out.println(String.format("Entry %d: User=%s, Action=%s, MessageNumber=%d, Time=%s",
                        i, user, action, currentMessageNumber, timestamp));

                Integer lastNumber = lastMessageNumberPerUser.get(user);
                if (lastNumber != null && currentMessageNumber >= lastNumber) {
                    System.out.println(String.format(
                            "ERROR: Message numbers should decrease in reverse chronological order for user %s: %d >= %d",
                            user, currentMessageNumber, lastNumber));
                    return false;
                }
                lastMessageNumberPerUser.put(user, currentMessageNumber);
            }
        }
        return true;
    }
}