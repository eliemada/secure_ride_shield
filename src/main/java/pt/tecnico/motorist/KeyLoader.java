package pt.tecnico.motorist;
import java.nio.charset.StandardCharsets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class KeyLoader {
    /**
     * Loads an EC private key from a PEM-formatted file.
     */

     public static PrivateKey loadECPrivateKey(String privateKeyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
        String keyString = new String(keyBytes, StandardCharsets.UTF_8);
        
        // Remove the PEM header and footer first
        String privateKeyPEM = keyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode the Base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        
        // Generate the private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }
    /**
     * Loads an EC public key from a PEM-formatted file.
     */
    public static PublicKey loadECPublicKey(String publicKeyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFile));
        String keyString = new String(keyBytes, StandardCharsets.UTF_8);
        
        // Remove the PEM header and footer first
        String publicKeyPEM = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode the Base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);
        
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Loads an RSA private key from a PEM-formatted file.
     */
    public static PrivateKey loadRSAPrivateKey(String privateKeyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
        String keyString = new String(keyBytes, StandardCharsets.UTF_8);
        
        // Remove the PEM header and footer first
        String privateKeyPEM = keyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode the Base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Loads an RSA public key from a PEM-formatted file.
     */
    public static PublicKey loadRSAPublicKey(String publicKeyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFile));
        String keyString = new String(keyBytes, StandardCharsets.UTF_8);
        
        // Remove the PEM header and footer first
        String publicKeyPEM = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode the Base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);
        
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}