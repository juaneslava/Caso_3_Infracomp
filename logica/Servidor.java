package logica;

import java.net.ServerSocket;
import java.net.Socket;

public class Servidor extends Thread {

    private int port;

    public Servidor(int port) {
        this.port = port;
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

}
