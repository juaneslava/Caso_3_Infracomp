package logica;

import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Cipher;

public class Cliente extends Thread {

    private String serverAddress;
    private int serverPort;

    private Socket socket;

    private InputStreamReader isr;
    private OutputStreamWriter osw;

    private BufferedReader in;
    private BufferedWriter out;

    private byte[] k_ab;
    private byte[] k_hmac;
    private byte[] iv;

    
    private PublicKey serverPublicKey;
    private String retoOriginal;

    private BigInteger G;
    private BigInteger P;
    private BigInteger Gx;
    private byte[] sharedSecretKey; // Clave para HMAC
    
    // Constructor to set server address and port
    public Cliente(String address, int port) {
        this.serverAddress = address;
        this.serverPort = port;
        this.serverPublicKey = readPublicKeyFromFile();
    }
    
    @Override
    public void run() {
        try {
            this.socket = new Socket(this.serverAddress, this.serverPort);
            isr = new InputStreamReader(socket.getInputStream());
            osw = new OutputStreamWriter(socket.getOutputStream());
            in = new BufferedReader(isr);
            out = new BufferedWriter(osw);
            enviarInicio();
            enviarReto();   // Envía el reto cifrado
            boolean validarReto = verificarReto();
            if (!validarReto) {
                return;
            }
            else
            {
                write("OK");
            }
            try {
                Thread.sleep(500);  // Espera para asegurar la recepción en el servidor
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            // Paso 9: Recibir G, P, y G^x del servidor
            recibirParametrosDiffieHellman();

            // Paso 13 y 14: Enviar solicitud
            enviarSolicitud("1", "10");

            // Paso 16: Recibir respuesta
            String estado = SecurityUtils.decryptWithAES(read(), k_ab, iv);
            String hmac = read();
            
            // Paso 17: Verificar
            if(!SecurityUtils.verifyHMC(estado, hmac, k_ab))
            {
                return;
            }
            
            // Paso 18: Enviar mensaje de terminar
            write("TERMINAR");


            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void enviarInicio() {
        write("SECINIT");
    }

    public void enviarReto() {
        // Generar un reto corto
        retoOriginal = "Best group of infracomp";
        String retoCifrado = cifrarMensaje(retoOriginal, serverPublicKey);
    
        if (retoCifrado != null && !retoCifrado.isEmpty()) {
            write(retoCifrado); // Envía el reto cifrado al servidor
        } else {
        }
    }

    public boolean verificarReto() {
        try {
            // Leer la respuesta `Rta` enviada por el servidor
            String respuesta = read();
    
            if (respuesta != null && respuesta.equals("Best group of infracomp")) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    private void recibirParametrosDiffieHellman() {
        try {
            G = new BigInteger(read());
            System.out.println("G: " + G);
            P = new BigInteger(read());
            System.out.println("P: " + P);
            Gx = new BigInteger(read());
            System.out.println("Gx: " + Gx);
            String firma = read();

            // Verificar la firma
            String concatenated = G.toString() + ";" + P.toString() + ";" + Gx.toString();
            if (!SecurityUtils.verificarFirma(concatenated, firma, serverPublicKey)) {
                System.out.println("Error en la verificación de la firma. Enviando ERROR.");
                write("ERROR");
                return;
            }
            else {
                write("OK");
            }

            // Generar G^y y calcular el secreto compartido
            SecureRandom random = new SecureRandom();
            BigInteger y = new BigInteger(512, random); // Valor secreto del cliente
            BigInteger Gy = G.modPow(y, P); // G^y mod P
            write(Gy.toString());

            // Calcular el secreto compartido (G^x)^y mod P = G^(xy) mod P
            BigInteger sharedSecret = Gx.modPow(y, P);
            System.out.println("Secreto compartido (G^(xy) mod P): " + sharedSecret);

            // Derivar claves k_w y k_hmac
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret.toByteArray());
            k_ab = Arrays.copyOfRange(digest, 0, 32); // Clave para cifrado AES
            k_hmac = Arrays.copyOfRange(digest, 32, 64); // Clave para HMAC

            // Obtener IV
            iv = read().getBytes();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public String cifrarMensaje(String mensaje, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    
            // Asegurarse de que el mensaje no excede el límite de 117 bytes
            byte[] mensajeBytes = mensaje.getBytes("UTF-8");
            if (mensajeBytes.length > 117) {
                return null;
            }
    
            // Cifrar y codificar en Base64
            byte[] encryptedBytes = cipher.doFinal(mensajeBytes);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String descifrarMensaje(String mensajeCifrado) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(mensajeCifrado);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
 
    public PublicKey readPublicKeyFromFile() {
        try {
            FileInputStream fis = new FileInputStream("public/public.key");
            byte[] encodedPublicKey = fis.readAllBytes();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);

            fis.close();
            return keyFactory.generatePublic(publicKeySpec);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void enviarSolicitud(String id_cliente, String id_paquete) {
        String hmac_cliente = SecurityUtils.generateHMC(id_cliente, k_ab);
        String hmac_paquete = SecurityUtils.generateHMC(id_paquete, k_ab);
        String cliente_encrypted = SecurityUtils.encryptWithAES(id_cliente, k_ab, iv);
        String paquete_encrypted = SecurityUtils.encryptWithAES(id_paquete, k_ab, iv);

        write(cliente_encrypted);
        write(hmac_cliente);
        write(paquete_encrypted);
        write(hmac_paquete);
    }

    public String read() {
        try {
            String message = in.readLine();
            while(message == null || message.isEmpty()) {
                Thread.sleep(1);
                message = in.readLine();
            }
            System.out.println("MENSAJE RECIBIDO POR CLIENTE: " + message);
            return message;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void write(String message) {
        try {
            out.write(message);
            out.newLine();
            out.flush(); // Ensure the message is sent immediately
            System.out.println("MENSAJE ENVIADO POR CLIENTE: " + message);
            Thread.sleep(1000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Cliente cliente = new Cliente("localhost", 5000);
        cliente.start();
    }
}
