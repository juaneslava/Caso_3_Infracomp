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

import javax.crypto.Cipher;

public class Servidor extends Thread{

    private ServerSocket serverSocket;

    private Socket clientSocket;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private InputStreamReader isr;
    private OutputStreamWriter osw;
    private BufferedReader in;
    private BufferedWriter out;
    private String retoRecibidoCifrado;
    
    public Servidor(int puerto) {
        try {
            this.serverSocket = new ServerSocket(puerto);
            readKeysFromFile();
            System.err.println("Server started.");
            this.clientSocket = serverSocket.accept();
            isr = new InputStreamReader(clientSocket.getInputStream());
            osw = new OutputStreamWriter(clientSocket.getOutputStream());
            in = new BufferedReader(isr);
            out = new BufferedWriter(osw);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {    
            recibirInicio(); // Recibir el mensaje "SECINIT" del cliente      
            recibirReto(); // Recibir el reto cifrado del cliente
            responderReto();
            esperarConfirmacion();
            clientSocket.close();
            serverSocket.close();
            System.out.println("Conexión cerrada en el servidor.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void recibirInicio() {
        try {
            String inicio = in.readLine();
            if ("SECINIT".equals(inicio)) {
                System.out.println("Inicio de sesión recibido.");
            } else {
                System.out.println("Error: Mensaje de inicio no válido.");
                // Opcional: podrías cerrar la conexión si el mensaje de inicio es incorrecto
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void recibirReto() {
        try {
            retoRecibidoCifrado = in.readLine(); // Lee el reto cifrado enviado por el cliente
            if (retoRecibidoCifrado == null || retoRecibidoCifrado.isEmpty()) {
                System.out.println("Error: Mensaje cifrado recibido es nulo o vacío.");
                return;
            }
            System.out.println("Reto cifrado recibido: " + retoRecibidoCifrado);
            System.out.println("Longitud del mensaje cifrado recibido (Base64): " + retoRecibidoCifrado.length());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void stopServer() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
                System.out.println("Server stopped.");
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

            System.out.println("Public key: " + publicKey);

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
            String retoRecibidoCifrado = in.readLine();
            System.out.println("Mensaje cifrado recibido: " + retoRecibidoCifrado);
    
            if (retoRecibidoCifrado != null && !retoRecibidoCifrado.isEmpty()) {
                System.out.println("Longitud del mensaje cifrado recibido (Base64): " + retoRecibidoCifrado.length());
    
                // Intentar descifrar el reto recibido
                String retoDescifrado = descifrarMensaje(retoRecibidoCifrado, privateKey);
    
                if (retoDescifrado != null) {
                    System.out.println("Reto descifrado: " + retoDescifrado);
    
                    // Enviar la respuesta al cliente
                    out.write(retoDescifrado + "\n");
                    out.newLine();
                    out.flush();
                    System.out.println("Rta enviada al cliente.");
                } else {
                    System.out.println("Error al descifrar el reto. Enviando mensaje de error al cliente.");
                    out.write("ERROR_DESCIFRADO\n");
                    out.flush();
                }
            } else {
                System.out.println("Error: Mensaje cifrado recibido es nulo o vacío.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void esperarConfirmacion() {
        try {
            System.out.println("Esperando confirmación del cliente...");
            
            // Leer confirmación ("OK" o "ERROR") del cliente
            String confirmacion = in.readLine();
            
            System.out.println("Confirmación recibida del cliente: " + confirmacion);
            
            if ("OK".equals(confirmacion)) {
                System.out.println("Cliente confirmó: Reto validado correctamente.");
            } else if ("ERROR".equals(confirmacion)) {
                System.out.println("Cliente indicó un error en la validación del reto.");
            } else {
                System.out.println("Mensaje inesperado del cliente: " + confirmacion);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    
    
    
            

    public static void main(String[] args) {
        Servidor servidor = new Servidor(5000);
        servidor.start();
    }
}
