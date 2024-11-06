package logica;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.math.BigInteger;


import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Servidor extends Thread{

    private ServerSocket serverSocket;

    private Socket clientSocket;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] k_ab;
    private byte[] iv;

    private InputStreamReader isr;
    private OutputStreamWriter osw;
    private BufferedReader in;
    private BufferedWriter out;
    private String retoRecibidoCifrado;

    private Map<String, Paquete> paquetes;

    // Declarar G, P y G^x
    private BigInteger G;
    private BigInteger P;
    private BigInteger Gx;
    private BigInteger x; // Valor secreto del servidor
    private byte[] sharedSecretKey; // Clave para HMAC
    
    public Servidor(int puerto) {
        try {
            this.serverSocket = new ServerSocket(puerto);
            readKeysFromFile();
            System.err.println("Server started.");
        } catch (Exception e) {
            e.printStackTrace();
        }
        paquetes = new HashMap<>();
    }
    
    @Override
    public void run() {
        try {    
            this.clientSocket = serverSocket.accept();
            isr = new InputStreamReader(clientSocket.getInputStream());
            osw = new OutputStreamWriter(clientSocket.getOutputStream());
            in = new BufferedReader(isr);
            out = new BufferedWriter(osw);
            recibirInicio(); // Recibir el mensaje "SECINIT" del cliente      
            recibirReto(); // Recibir el reto cifrado del cliente
            responderReto();
            esperarConfirmacion();

             // Paso 7 y 8: Inicializar Diffie-Hellman
            enviarParametrosDiffieHellman(); // Enviar G, P, G^x y firma al cliente
            // Paso 10: Recibir "OK" o "ERROR" de verificación del cliente
            String respuesta = read();
            System.out.println("Respuesta de verificación del cliente (paso 10): " + respuesta);

            if ("OK".equals(respuesta)) {
                System.out.println("Cliente verificó correctamente los parámetros Diffie-Hellman.");
            } else {
                System.out.println("Error en la verificación de parámetros Diffie-Hellman por parte del cliente.");
            }
            
            // Paso 15: Recibir la solicitud del cliente
            String id_cliente = SecurityUtils.decryptWithAES(read(), k_ab, iv);
            String hmac_cliente = read();
            String id_paquete = SecurityUtils.decryptWithAES(read(), k_ab, iv);
            String hmac_paquete = read();

            // Paso 16: Enviar respuesta
            atenderSolicitud(id_cliente, hmac_cliente, id_paquete, hmac_paquete);

            clientSocket.close();
            serverSocket.close();
            // System.out.println("Conexión cerrada en el servidor.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void recibirInicio() {
        try {
            String inicio = read();
            if ("SECINIT".equals(inicio)) {
                // System.out.println("Inicio de sesión recibido.");
            } else {
                // System.out.println("Error: Mensaje de inicio no válido.");
                // Opcional: podrías cerrar la conexión si el mensaje de inicio es incorrecto
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void recibirReto() {
        try {
            retoRecibidoCifrado = read(); // Lee el reto cifrado enviado por el cliente
            if (retoRecibidoCifrado == null || retoRecibidoCifrado.isEmpty()) {
                // System.out.println("Error: Mensaje cifrado recibido es nulo o vacío.");
                return;
            }
            // System.out.println("Reto cifrado recibido: " + retoRecibidoCifrado);
            // System.out.println("Longitud del mensaje cifrado recibido (Base64): " + retoRecibidoCifrado.length());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void stopServer() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
                // System.out.println("Server stopped.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void readKeysFromFile() {
        try {
            FileInputStream fisPublic = new FileInputStream("public/public.key");
            FileInputStream fisPrivate = new FileInputStream("server/private.key");
            
            byte[] publicKeyBytes = fisPublic.readAllBytes();
            byte[] privateKeyBytes = fisPrivate.readAllBytes();
            
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            
            this.publicKey = keyFactory.generatePublic(publicKeySpec);
            this.privateKey = keyFactory.generatePrivate(privateKeySpec);

            // System.out.println("Public key: " + publicKey);

            fisPublic.close();
            fisPrivate.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        

    }

    public String cifrarMensaje(String mensaje, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(mensaje.getBytes());
            return new String(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String cifrarMensaje(String mensaje, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedBytes = cipher.doFinal(mensaje.getBytes());
            return new String(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String descifrarMensaje(String mensajeCifrado, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] encryptedBytes = mensajeCifrado.getBytes();
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String descifrarMensaje(String mensajeCifrado, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
    
            // Decodificar de Base64 y descifrar
            byte[] encryptedBytes = Base64.getDecoder().decode(mensajeCifrado);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void responderReto() {
        try {
            //String retoRecibidoCifrado = in.readLine();
            System.out.println("Mensaje cifrado recibido: " + retoRecibidoCifrado);
    
            if (retoRecibidoCifrado != null && !retoRecibidoCifrado.isEmpty()) {
                // System.out.println("Longitud del mensaje cifrado recibido (Base64): " + retoRecibidoCifrado.length());
    
                // Intentar descifrar el reto recibido
                String retoDescifrado = descifrarMensaje(retoRecibidoCifrado, privateKey);
    
                if (retoDescifrado != null) {
                    // System.out.println("Reto descifrado: " + retoDescifrado);
    
                    // Enviar la respuesta al cliente
                    write(retoDescifrado);
                    // System.out.println("Rta enviada al cliente.");
                } else {
                    // System.out.println("Error al descifrar el reto. Enviando mensaje de error al cliente.");
                    write("ERROR_DESCIFRADO");
                    
                }
            } else {
                // System.out.println("Error: Mensaje cifrado recibido es nulo o vacío.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void esperarConfirmacion() {
        try {
            // System.out.println("Esperando confirmación del cliente...");
            
            // Leer confirmación ("OK" o "ERROR") del cliente
            String confirmacion = read();
            
            // System.out.println("Confirmación recibida del cliente: " + confirmacion);
            
            if ("OK".equals(confirmacion)) {
                // System.out.println("Cliente confirmó: Reto validado correctamente.");
            } else if ("ERROR".equals(confirmacion)) {
                // System.out.println("Cliente indicó un error en la validación del reto.");
            } else {
                // System.out.println("Mensaje inesperado del cliente: " + confirmacion);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para inicializar los valores de Diffie-Hellman
    public void initDiffieHellmanParameters() {
        SecureRandom random = new SecureRandom();
        G = BigInteger.probablePrime(512, random); // Generar G
        P = BigInteger.probablePrime(512, random); // Generar P
        x = new BigInteger(512, random); // Generar el secreto x
        Gx = G.modPow(x, P); // Calcular G^x

        System.out.println("Valores generados para Diffie-Hellman:");
        System.out.println("G: " + G);
        System.out.println("P: " + P);
        System.out.println("G^x: " + Gx);
    }

    private String calculateHMAC(String data, byte[] key) throws Exception {
        Mac hmac = Mac.getInstance("HMACSHA384");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HMACSHA384");
        hmac.init(secretKey);
        return Base64.getEncoder().encodeToString(hmac.doFinal(data.getBytes()));

    }
    // Método para enviar G, P y G^x al cliente
    public void enviarParametrosDiffieHellman() {
        try {
            // Paso 7: Generar valores de Diffie-Hellman
            SecureRandom random = new SecureRandom();
            
            // Generador G y número primo P
            BigInteger G = new BigInteger("2"); // Generalmente se usa 2 o 5 como generador
            BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                                        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
                                        + "FFFFFFFFFFFFFFFF", 16);
            
            // Elegir un valor privado x aleatorio
            BigInteger x = new BigInteger(512, random); // 512 bits aleatorios para x
            BigInteger Gx = G.modPow(x, P); // G^x mod P
    
            // Enviar G, P y G^x al cliente
            write(G.toString());
            System.out.println("Valor de G enviado al cliente.");
            write(P.toString());
            System.out.println("Valor de P enviado al cliente.");
            write(Gx.toString());
            System.out.println("Valor de G^x enviado al cliente.");
            System.out.println("Valores generados para Diffie-Hellman:");
            System.out.println("G: " + G);
            System.out.println("P: " + P);
            System.out.println("G^x: " + Gx);
    
            // Recibir G^y del cliente
            BigInteger Gy = new BigInteger(read()); // El cliente envía su propio G^y
            System.out.println("Valor recibido de G^y del cliente: " + Gy);
    
            // Calcular el secreto compartido (G^y)^x mod P = G^(xy) mod P
            BigInteger sharedSecret = Gy.modPow(x, P);
            System.out.println("Secreto compartido (G^(xy) mod P): " + sharedSecret);
    
            // Paso 8: Derivar claves k_w y k_hmac a partir del secreto compartido
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret.toByteArray());
    
            // Verificar la longitud del digest generado
            if (digest.length != 64) {
                System.out.println("Error: digest no tiene la longitud esperada de 64 bytes.");
                return;
            }
    
            // Dividir el digest en dos mitades de 32 bytes cada una para k_w y k_hmac
            byte[] k_w = Arrays.copyOfRange(digest, 0, 32); // Clave para cifrado
            byte[] k_hmac = Arrays.copyOfRange(digest, 32, 64); // Clave para HMAC
    
            // Crear SecretKeySpec para AES y HMAC
            SecretKeySpec keySpecCifrado = new SecretKeySpec(k_w, "AES");
            SecretKeySpec keySpecHMAC = new SecretKeySpec(k_hmac, "HmacSHA384");
    
            // Calcular HMAC de los valores G, P y G^x usando k_hmac
            String concatenatedParams = G.toString() + P.toString() + Gx.toString();
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(keySpecHMAC);
            byte[] hmacBytes = hmac.doFinal(concatenatedParams.getBytes());
    
            // Convertir el HMAC a una cadena hexadecimal para enviar
            StringBuilder hmacHex = new StringBuilder();
            for (byte b : hmacBytes) {
                hmacHex.append(String.format("%02x", b));
            }
            String hmacString = hmacHex.toString();
    
            // Enviar el HMAC al cliente
            write(hmacString);
            System.out.println("HMAC enviado al cliente: " + hmacString);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    

    public void atenderSolicitud(String id_cliente, String hmac_cliente, String id_paquete, String hmac_paquete){
        if (SecurityUtils.verifyHMC(id_paquete, hmac_paquete, k_ab)) {
            if (SecurityUtils.verifyHMC(id_cliente, hmac_cliente, k_ab)) {
                String estado = verEstadoPaquete(id_paquete);
                String hmac_estado = SecurityUtils.generateHMC(estado, k_ab);
                String estado_encrypted = SecurityUtils.encryptWithAES(estado, k_ab, iv);
                write(estado_encrypted);
                write(hmac_estado);
            } else {
                write("ERROR");
            }
        } else {
            write("ERROR");
        }
    }

    public String verEstadoPaquete(String id) {
        Paquete paquete = paquetes.get(id);
        if (paquete == null) {
            return "ERROR";
        } else {
            return String.valueOf(paquete.getEstado());
        }
    }

    public void write(String message) {
        try {
            out.write(message + "\n");
            //out.newLine();
            out.flush();
            System.out.println("WRITE DEL SERVIDOR: " + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String read() {
        try {
            String message = in.readLine();
            System.out.println("MENSAJE RECIBIDO POR EL SERVIDOR: " + message);
            return message;
        } catch (Exception e ) {
            e.printStackTrace();
            return null;
        }
    }
            

    public static void main(String[] args) {
        Servidor servidor = new Servidor(5000);
        servidor.start();
    }
}
