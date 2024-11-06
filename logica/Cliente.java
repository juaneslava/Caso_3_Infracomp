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
        try
        {
            this.socket = new Socket(this.serverAddress, this.serverPort);
            isr = new InputStreamReader(socket.getInputStream());
            osw = new OutputStreamWriter(socket.getOutputStream());
            in = new BufferedReader(isr);
            out = new BufferedWriter(osw);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {
            enviarInicio();
            enviarReto();   // Envía el reto cifrado
            boolean validarReto = verificarReto();
            if (!validarReto) {
                System.out.println("No se pudo validar el reto.");
                return;
            }
            else
            {
                System.out.println("Reto validado. Enviando OK.");
                write("OK");
                System.out.println("último OK fue enviado.");
            }
            Thread.sleep(500);  // Espera para asegurar la recepción en el servidor

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
                System.out.println("Error: El mensaje ha sido modificado.");
                return;
            }
            System.out.println("Estado del paquete: " + estado);
            
            // Paso 18: Enviar mensaje de terminar
            write("TERMINAR");


            socket.close();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void enviarInicio() {
        write("SECINIT");
    }

    public void enviarReto() {
        // Generar un reto corto
        String reto = "Best group of infracomp";
        String retoCifrado = cifrarMensaje(reto, serverPublicKey);
    
        if (retoCifrado != null && !retoCifrado.isEmpty()) {
            System.out.println("Reto cifrado a enviar: " + retoCifrado);
            write(retoCifrado); // Envía el reto cifrado al servidor
            System.out.println("Reto enviado al servidor.");
        } else {
            System.out.println("Error: Reto cifrado es nulo o vacío.");
        }
    }

    public boolean verificarReto() {
        try {
            // Leer la respuesta `Rta` enviada por el servidor
            String respuesta = read();
            System.out.println("Respuesta recibida del servidor: " + respuesta);
    
            if (respuesta != null && respuesta.equals("Best group of infracomp")) {
                System.out.println("Reto validado correctamente. Enviando OK.");
                return true;
            } else {
                System.out.println("Fallo en la validación del reto. Enviando ERROR.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    private String calculateHMAC(String data, byte[] key) throws Exception {
        Mac hmac = Mac.getInstance("HMACSHA384");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HMACSHA384");
        hmac.init(secretKey);
        return Base64.getEncoder().encodeToString(hmac.doFinal(data.getBytes()));
    }
    
    private void recibirParametrosDiffieHellman() {
        try {
            G = new BigInteger(read());
            System.out.println("G: " + G);
            P = new BigInteger(read());
            System.out.println("P: " + P);
            Gx = new BigInteger(read());
            System.out.println("Gx: " + Gx);
            String hmacRecibido = read();

            // Concatenar G, P y G^x para verificar
            String data = G.toString() + P.toString() + Gx.toString();
            String hmacCalculado = calculateHMAC(data, sharedSecretKey);

            // Verificar el HMAC
            if (hmacCalculado.equals(hmacRecibido)) {
                System.out.println("HMAC verificado exitosamente. Enviando OK.");
                write("OK");

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
                sharedSecretKey = Arrays.copyOfRange(digest, 32, 64); // Clave para HMAC

            } else {
                System.out.println("Error en la verificación del HMAC. Enviando ERROR.");
                write("ERROR");
            }
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
                System.out.println("Error: El mensaje es demasiado largo para cifrar con RSA de 1024 bits.");
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
            return in.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void write(String message) {
        try {
            out.write(message+ "\n");
            //out.newLine();
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Cliente cliente = new Cliente("localhost", 5000);
        cliente.start();
    }
}
