package logica;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;

public class SecurityUtils {

    public static String encryptWithAES(String message, byte[] key, byte[] iv) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptWithAES(String encryptedMessage, byte[] key, byte[] iv) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String generateHMC(String message, byte[] key) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA384");
            Mac mac = Mac.getInstance("HmacSHA384");
            mac.init(secretKey);

            byte[] hmacBytes = mac.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verifyHMC(String message, String hmac, byte[] key) {
        try {
            String newHmac = generateHMC(message, key);
            return newHmac.equals(hmac);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String firmarMensaje(String mensaje, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(mensaje.getBytes());
            byte[] signedBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verificarFirma(String mensaje, String firma, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(mensaje.getBytes());
            byte[] firmaBytes = Base64.getDecoder().decode(firma);
            return signature.verify(firmaBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] generateRandomBytes(int length) {
        byte[] randomBytes = new byte[length];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return randomBytes;
    }
}
