package logica;

import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Cliente extends Thread {

    private String serverAddress;
    private int serverPort;

    private Socket socket;

    private InputStreamReader isr;
    private OutputStreamWriter osw;

    private BufferedReader in;
    private BufferedWriter out;

    
    private PublicKey serverPublicKey;
    
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
            boolean validarReto = verificarReto();
            if (!validarReto) {
                System.out.println("No se pudo validar el reto.");
                return;
            }
            else
            {
                System.out.println("Reto validado.");
            }
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public boolean verificarReto() {
        String reto = "Best group of infracomp";
        String respuesta = cifrarMensaje(reto, serverPublicKey);
        try {
            out.write(respuesta + "\n");
            out.newLine();
            out.flush();
            String response = in.readLine();
            return response.equals("OK");
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String cifrarMensaje(String mensaje, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(mensaje.getBytes());
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

    public static void main(String[] args) {
        Cliente cliente = new Cliente("localhost", 5000);
        cliente.start();
    }
}
