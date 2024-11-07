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
import java.util.Map;
import java.math.BigInteger;


import javax.crypto.Cipher;

public class Delegado extends Thread{

    private Socket clientSocket;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] k_ab;
    private byte[] k_hmac;
    private byte[] iv;

    private InputStreamReader isr;
    private OutputStreamWriter osw;
    private BufferedReader in;
    private BufferedWriter out;
    private String retoRecibidoCifrado;

    private Map<String, Paquete> paquetes = Servidor.paquetes;

    // Declarar G, P y G^x
    private BigInteger G;
    private BigInteger P;
    private BigInteger Gx;
    private BigInteger x; // Valor secreto del servidor

    private boolean iterativo;
    
    public Delegado(Socket clienSocket, boolean iterativo) {
        try {
            this.clientSocket = clienSocket;
            readKeysFromFile();
            System.err.println("Server started.");
            this.iterativo = iterativo;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public void run() {
        try {    

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

            boolean validacion = validateOK(respuesta);
            if (!validacion) {
                return;
            }

            // Paso 11: Calcular la clave compartida
            calcularLlaveCompartida();

            // Paso 12: Generar IV
            generarIV();

            // Paso 15: Recibir la solicitud del cliente
            int repeticiones = 1;
            if (iterativo) {
                repeticiones = 32;
            }
            for (int i = 0; i < repeticiones; i++) {
                String id_cliente = SecurityUtils.decryptWithAES(read(), k_ab, iv);
                String hmac_cliente = read();
                String id_paquete = SecurityUtils.decryptWithAES(read(), k_ab, iv);
                String hmac_paquete = read();
    
    
                // Paso 16: Enviar respuesta
                atenderSolicitud(id_cliente, hmac_cliente, id_paquete, hmac_paquete);
                System.out.println("Delegado: Atendiendo solicitud " + i);
            }

            // Paso 18: Recibir mensaje de terminar
            String terminar = read();
            System.out.println("Delegado: " + terminar);
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void recibirInicio() {
        try {
            String inicio = read();
            if ("SECINIT".equals(inicio)) {
            } else {
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
                return;
            }
        } catch (Exception e) {
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
            if (retoRecibidoCifrado != null && !retoRecibidoCifrado.isEmpty()) {
                // Intentar descifrar el reto recibido
                String retoDescifrado = descifrarMensaje(retoRecibidoCifrado, privateKey);
                if (retoDescifrado != null) {
                    // Enviar la respuesta al cliente
                    write(retoDescifrado);
                } else {
                    write("ERROR_DESCIFRADO");
                }
            } else {
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void esperarConfirmacion() {
        try {
            // Leer confirmación ("OK" o "ERROR") del cliente
            String confirmacion = read();
            if ("OK".equals(confirmacion)) {
            } else if ("ERROR".equals(confirmacion)) {
            } else {
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para inicializar los valores de Diffie-Hellman
    public void initDiffieHellmanParameters() {
        // Paso 7: Generar valores de Diffie-Hellman
        SecureRandom random = new SecureRandom();
            
        // Generador G y número primo P
        G = new BigInteger("2"); // Generalmente se usa 2 o 5 como generador
        P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
                                    + "FFFFFFFFFFFFFFFF", 16);
        // Elegir un valor privado x aleatorio
        x = new BigInteger(512, random); // 512 bits aleatorios para x
        Gx = G.modPow(x, P); // G^x mod P
    }

    // Método para enviar G, P y G^x al cliente
    public void enviarParametrosDiffieHellman() {
        try {

            // Paso 7: Generar valores de Diffie-Hellman
            initDiffieHellmanParameters();

            // Enviar G, P y G^x al cliente
            write(G.toString());
            write(P.toString());
            write(Gx.toString());

            // Firmar los valores G, P y G^x
            String concatenatedParams = G.toString() + ";" + P.toString() + ";" + Gx.toString();
            String signature = SecurityUtils.firmarMensaje(concatenatedParams, privateKey);
            write(signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void calcularLlaveCompartida() {
        try {
            // Recibir G^y del cliente    
            BigInteger Gy = new BigInteger(read()); // El cliente envía su propio G^y
            // Calcular el secreto compartido (G^y)^x mod P = G^(xy) mod P
            BigInteger sharedSecret = Gy.modPow(x, P);


            // Paso 8: Derivar claves k_w y k_hmac a partir del secreto compartido
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret.toByteArray());

            // Verificar la longitud del digest generado
            if (digest.length != 64) {
                return;
            }

            // Dividir el digest en dos mitades de 32 bytes cada una para k_w y k_hmac
            k_ab = Arrays.copyOfRange(digest, 0, 32); // Clave para cifrado AES
            k_hmac = Arrays.copyOfRange(digest, 32, 64); // Clave para HMAC
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generarIV() {
        // Generar IV aleatorio
        SecureRandom random = new SecureRandom();
        iv = new byte[16]; // El IV para AES en modo CBC es de 16 bytes
        random.nextBytes(iv);
        // Convertir IV a Base64 antes de enviar
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        write(ivBase64);
    }


    public boolean validateOK(String message) {
        if ("OK".equals(message)) {
            return true;
        } else {
            return false;
        }
    }

    public void atenderSolicitud(String id_cliente, String hmac_cliente, String id_paquete, String hmac_paquete){
        if (SecurityUtils.verifyHMC(id_paquete, hmac_paquete, k_hmac)) {
            if (SecurityUtils.verifyHMC(id_cliente, hmac_cliente, k_hmac)) {
                String estado = verEstadoPaquete(id_paquete);
                String estado_encrypted = SecurityUtils.encryptWithAES(estado, k_ab, iv);
                String hmac_estado = SecurityUtils.generateHMC(estado, k_hmac);
                write(estado_encrypted);
                write(hmac_estado);
            } else {
                System.out.println("Delegado: ERROR");
                write("ERROR");
            }
        } else {
            System.out.println("Delegado: ERROR");
            write("ERROR");
        }
    }

    public String verEstadoPaquete(String id) {
        Paquete paquete = paquetes.get(id);
        if (paquete == null) {
            return "DESCONOCIDO";
        } else {
            return String.valueOf(paquete.getEstado());
        }
    }

    public void write(String message) {
        try {
            out.write(message + "\n");
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String read() {
        try {
            String message = in.readLine();
            return message;
        } catch (Exception e ) {
            e.printStackTrace();
            return null;
        }
    }
     
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static void main(String[] args) {
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(5000);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                Delegado delegado = new Delegado(clientSocket, false);
                delegado.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
