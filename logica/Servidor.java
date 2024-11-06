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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

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
            String retoRecibidoCifrado = read();
            // System.out.println("Mensaje cifrado recibido: " + retoRecibidoCifrado);
    
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
            out.newLine();
            out.flush(); // Ensure the message is sent immediately
            System.out.println("MENSAJE ENVIADO POR EL SERVIDOR: " + message);
        } catch (Exception e) {
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
