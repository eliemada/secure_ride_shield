package pt.tecnico.motorist;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 * FirmwareCrypto provides cryptographic operations for protecting and verifying
 * vehicle firmware updates.
 * This class implements a hybrid encryption scheme using AES-GCM for data
 * encryption and RSA-OAEP for key protection,
 * along with ECDSA for digital signatures to ensure authenticity and integrity.
 * 
 * The class uses the following cryptographic primitives:
 * - AES-GCM with 256-bit keys for firmware encryption
 * - RSA-OAEP with SHA-256 for key encapsulation
 * - ECDSA with SHA3-256 for digital signatures
 * - BouncyCastle as the security provider
 * 
 */
public class FirmwareCrypto {
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String ECDSA_ALGORITHM = "SHA3-256withECDSA";
    private static final String RSA_CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String RSA_PROVIDER = "BC";
    private static final int GCM_TAG_LENGTH = 128;
    private static final Gson gson = new Gson();
    private static final boolean DEBUG = false;

    /**
     * Logs debug messages if debugging is enabled.
     *
     * @param message The debug message to log
     */
    private static void debug(String message) {
        if (DEBUG) {
            System.out.println("[FirmwareCrypto Debug] " + message);
        }
    }

    // Initialize BouncyCastle security provider
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Protects firmware data by applying encryption and digital signature.
     * The process involves:
     * 1. Generating an AES key and encrypting the firmware using AES-GCM
     * 2. Encrypting the AES key with the car's public RSA key
     * 3. Creating a digital signature over all critical fields using the
     * manufacturer's private key
     * 
     * @param firmwareJson           JSON string containing firmware data including
     *                               ID, content, and version
     * @param manufacturerPrivateKey The manufacturer's private key for signing
     * @param carPublicKey           The target vehicle's public key for encrypting
     *                               the session key
     * @return A JSON string containing the protected firmware data, encrypted key,
     *         IV, and signature
     * @throws Exception if any cryptographic operation fails, including:
     *                   - Invalid key formats or algorithms
     *                   - Encryption/decryption failures
     *                   - Signature generation errors
     *                   - JSON parsing/generation errors
     */
    public static String protect(String firmwareJson, PrivateKey manufacturerPrivateKey,
            PublicKey carPublicKey) throws Exception {
        try {
            debug("Starting firmware protection");
            debug("Manufacturer Private Key Algorithm: " + manufacturerPrivateKey.getAlgorithm());
            debug("Car Public Key Algorithm: " + carPublicKey.getAlgorithm());
            debug("Input firmware: " + firmwareJson);

            // Parse the firmware JSON
            JsonObject firmwareObject = gson.fromJson(firmwareJson, JsonObject.class);
            debug("Parsed firmware object successfully");

            // Extract metadata for verification
            String firmwareId = firmwareObject.get("firmwareID").getAsString();
            String content = firmwareObject.get("content").getAsString();
            String version = firmwareObject.get("version").getAsString();
            String nonce = java.util.UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();

            // Convert firmware to bytes for encryption
            byte[] plainBytes = firmwareJson.getBytes(StandardCharsets.UTF_8);
            debug("Plain bytes length: " + plainBytes.length);

            // Generate AES key for encryption
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            debug("Generated AES key");

            // Generate IV for GCM mode
            byte[] iv = new byte[12];
            SecureRandom random = SecureRandom.getInstanceStrong();
            random.nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            debug("Generated IV");

            // Encrypt the firmware
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM, "BC");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            byte[] cipherText = aesCipher.doFinal(plainBytes);
            debug("Encrypted firmware, cipherText length: " + cipherText.length);

            // Encrypt the AES key with car's public key
            debug("Setting up RSA cipher for AES key encryption");
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM, RSA_PROVIDER);
            debug("RSA Cipher provider: " + rsaCipher.getProvider().getName());
            debug("RSA Cipher algorithm: " + rsaCipher.getAlgorithm());
            debug("RSA Key format: " + carPublicKey.getFormat());
            debug("RSA Key class: " + carPublicKey.getClass().getName());

            rsaCipher.init(Cipher.ENCRYPT_MODE, carPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            debug("AES key encrypted successfully, length: " + encryptedAesKey.length);
            debug("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedAesKey));

            // Hash all critical fields
            MessageDigest digest = MessageDigest.getInstance("SHA3-256", "BC");
            digest.update(cipherText);
            digest.update(encryptedAesKey);
            digest.update(iv);
            digest.update(nonce.getBytes(StandardCharsets.UTF_8));
            digest.update(Long.toString(timestamp).getBytes(StandardCharsets.UTF_8));
            digest.update(firmwareId.getBytes(StandardCharsets.UTF_8));
            digest.update(version.getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            debug("Created hash of all fields, length: " + hash.length);

            // Sign the hash
            Signature ecdsaSign = Signature.getInstance(ECDSA_ALGORITHM, "BC");
            ecdsaSign.initSign(manufacturerPrivateKey);
            ecdsaSign.update(hash);
            byte[] signature = ecdsaSign.sign();
            debug("Created signature, length: " + signature.length);

            // Create protected firmware message
            JsonObject protectedFirmware = new JsonObject();
            protectedFirmware.addProperty("cipherText", Base64.getEncoder().encodeToString(cipherText));
            protectedFirmware.addProperty("encryptedAesKey", Base64.getEncoder().encodeToString(encryptedAesKey));
            protectedFirmware.addProperty("iv", Base64.getEncoder().encodeToString(iv));
            protectedFirmware.addProperty("signature", Base64.getEncoder().encodeToString(signature));
            protectedFirmware.addProperty("firmwareID", firmwareId);
            protectedFirmware.addProperty("version", version);
            protectedFirmware.addProperty("type", "FIRMWARE_UPDATE");
            protectedFirmware.addProperty("timestamp", timestamp);
            protectedFirmware.addProperty("nonce", nonce);

            String result = gson.toJson(protectedFirmware);
            debug("Created protected firmware message");
            return result;

        } catch (Exception e) {
            debug("Error in protect: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Decrypts and recovers protected firmware data using the vehicle's private
     * key.
     * The process involves:
     * 1. Decrypting the session key using the vehicle's private RSA key
     * 2. Using the recovered session key to decrypt the firmware data
     * 
     * Note: This method does not verify the signature. Use the check() method first
     * to verify the firmware's authenticity.
     *
     * @param protectedFirmware JSON string containing the protected firmware data
     * @param carPrivateKey     The vehicle's private key for decrypting the session
     *                          key
     * @return The original firmware JSON string
     * @throws Exception if any cryptographic operation fails, including:
     *                   - Invalid key formats or algorithms
     *                   - Decryption failures
     *                   - JSON parsing errors
     *                   - Authentication tag verification failures in GCM mode
     */
    public static String unprotect(String protectedFirmware, PrivateKey carPrivateKey)
            throws Exception {
        try {
            debug("Starting firmware unprotection");
            debug("Car Private Key Algorithm: " + carPrivateKey.getAlgorithm());
            debug("Car Private Key Format: " + carPrivateKey.getFormat());
            debug("Car Private Key Class: " + carPrivateKey.getClass().getName());

            // Parse the protected firmware message
            JsonObject protectedFirmwareObj = gson.fromJson(protectedFirmware, JsonObject.class);
            debug("Parsed protected firmware JSON successfully");

            // Extract components
            byte[] cipherText = Base64.getDecoder().decode(protectedFirmwareObj.get("cipherText").getAsString());
            byte[] encryptedAesKey = Base64.getDecoder()
                    .decode(protectedFirmwareObj.get("encryptedAesKey").getAsString());
            byte[] iv = Base64.getDecoder().decode(protectedFirmwareObj.get("iv").getAsString());

            debug("CipherText length: " + cipherText.length);
            debug("Encrypted AES key length: " + encryptedAesKey.length);
            debug("IV length: " + iv.length);
            debug("Received encrypted AES key (Base64): " + protectedFirmwareObj.get("encryptedAesKey").getAsString());

            // Decrypt the AES key
            debug("Setting up RSA cipher for AES key decryption");
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM, RSA_PROVIDER);
            debug("RSA Cipher provider: " + rsaCipher.getProvider().getName());
            debug("RSA Cipher algorithm: " + rsaCipher.getAlgorithm());
            debug("RSA Cipher parameters: "
                    + (rsaCipher.getParameters() != null ? rsaCipher.getParameters().toString() : "null"));

            rsaCipher.init(Cipher.DECRYPT_MODE, carPrivateKey);
            debug("RSA Cipher initialized successfully");

            try {
                byte[] decryptedKeyBytes = rsaCipher.doFinal(encryptedAesKey);
                debug("AES key decrypted successfully, length: " + decryptedKeyBytes.length);
                SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(decryptedKeyBytes, "AES");

                // Decrypt the firmware
                GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM, "BC");
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
                byte[] plainBytes = aesCipher.doFinal(cipherText);
                debug("Firmware decrypted successfully");
                debug("Decrypted length: " + plainBytes.length);

                String result = new String(plainBytes, StandardCharsets.UTF_8);
                debug("Decrypted content: " + result);

                return result;
            } catch (Exception e) {
                debug("Failed to decrypt AES key: " + e.getMessage());
                debug("Exception class: " + e.getClass().getName());
                if (e.getCause() != null) {
                    debug("Cause: " + e.getCause().getMessage());
                }
                throw e;
            }
        } catch (Exception e) {
            debug("Error in unprotect: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Verifies the authenticity and integrity of protected firmware using the
     * manufacturer's public key.
     * The verification process:
     * 1. Reconstructs the verification hash from all critical fields
     * 2. Verifies the ECDSA signature using the manufacturer's public key
     * 
     * @param protectedFirmware     JSON string containing the protected firmware
     *                              data
     * @param manufacturerPublicKey The manufacturer's public key for signature
     *                              verification
     * @return true if the signature is valid, false otherwise
     * @throws Exception if any cryptographic operation fails, including:
     *                   - Invalid key formats or algorithms
     *                   - Signature verification errors
     *                   - JSON parsing errors
     */
    public static boolean check(String protectedFirmware, PublicKey manufacturerPublicKey) throws Exception {
        try {
            debug("Starting signature verification");
            debug("Manufacturer Public Key Algorithm: " + manufacturerPublicKey.getAlgorithm());
            debug("Manufacturer Public Key Format: " + manufacturerPublicKey.getFormat());

            JsonObject protectedFirmwareObj = gson.fromJson(protectedFirmware, JsonObject.class);
            debug("Parsed protected firmware JSON successfully");

            // Extract components for verification
            byte[] cipherText = Base64.getDecoder().decode(protectedFirmwareObj.get("cipherText").getAsString());
            byte[] encryptedAesKey = Base64.getDecoder()
                    .decode(protectedFirmwareObj.get("encryptedAesKey").getAsString());
            byte[] iv = Base64.getDecoder().decode(protectedFirmwareObj.get("iv").getAsString());
            byte[] signature = Base64.getDecoder().decode(protectedFirmwareObj.get("signature").getAsString());
            String nonce = protectedFirmwareObj.get("nonce").getAsString();
            long timestamp = protectedFirmwareObj.get("timestamp").getAsLong();
            String firmwareId = protectedFirmwareObj.get("firmwareID").getAsString();
            String version = protectedFirmwareObj.get("version").getAsString();

            debug("CipherText length: " + cipherText.length);
            debug("Encrypted AES key length: " + encryptedAesKey.length);
            debug("IV length: " + iv.length);
            debug("Signature length: " + signature.length);

            // Hash all critical fields
            MessageDigest digest = MessageDigest.getInstance("SHA3-256", "BC");
            digest.update(cipherText);
            digest.update(encryptedAesKey);
            digest.update(iv);
            digest.update(nonce.getBytes(StandardCharsets.UTF_8));
            digest.update(Long.toString(timestamp).getBytes(StandardCharsets.UTF_8));
            digest.update(firmwareId.getBytes(StandardCharsets.UTF_8));
            digest.update(version.getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            debug("Hash computed, length: " + hash.length);

            // Verify signature
            Signature ecdsaVerify = Signature.getInstance(ECDSA_ALGORITHM, "BC");
            ecdsaVerify.initVerify(manufacturerPublicKey);
            ecdsaVerify.update(hash);

            boolean result = ecdsaVerify.verify(signature);
            debug("Signature verification result: " + result);

            return result;

        } catch (Exception e) {
            debug("Error in check: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
}