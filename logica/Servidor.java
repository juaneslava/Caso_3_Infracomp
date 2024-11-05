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

    private Map<String, Paquete> paquetes;
    
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
        paquetes = new HashMap<>();
    }

    @Override
    public void run() {
        try {          
            responderReto();

            // Paso 15: Recibir la solicitud del cliente
            String id_cliente = SecurityUtils.decryptWithAES(read(), k_ab, iv);
            String hmac_cliente = read();
            String id_paquete = SecurityUtils.decryptWithAES(read(), k_ab, iv);
            String hmac_paquete = read();

            // Paso 16: Enviar respuesta
            atenderSolicitud(id_cliente, hmac_cliente, id_paquete, hmac_paquete);

            clientSocket.close();
            serverSocket.close();
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
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = mensajeCifrado.getBytes();
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void responderReto() {
        try {
            String reto = in.readLine();
            System.out.println("Reto recibido: " + reto);
            String respuesta = descifrarMensaje(reto, privateKey);
            System.out.println("Respuesta: " + respuesta);
            out.write(respuesta + "\n");
            out.newLine();
            out.flush();
        } catch (IOException e) {
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
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String read() {
        try {
            return in.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
            

    public static void main(String[] args) {
        Servidor servidor = new Servidor(5000);
        servidor.start();
    }
}
