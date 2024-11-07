package logica;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;

public class Servidor extends Thread {

    private int port;

    public static Map<String, Paquete> paquetes; 

    public Servidor(int port) {
        this.port = port;
        paquetes = new java.util.HashMap<>();
    }

    @Override
    public void run() {
        iniciarServidor();
    }

    public void iniciarServidor() {
        try (ServerSocket serverSocket = new ServerSocket(this.port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                Delegado delegado = new Delegado(clientSocket);
                delegado.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void llenarPaquetes(Map<String, Paquete> paquetes, int numClientes, int numPaquetes) {
        for (int i = 0; i < numPaquetes; i++) {
            Integer estado = (int) (Math.random() * 6);
            Paquete paquete = new Paquete("Paquete" + i, "Cliente" + (i % numClientes), estado);
            paquetes.put(paquete.getId(), paquete);
        }
    }

}
