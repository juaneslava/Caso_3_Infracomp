package logica;
import java.util.Scanner;

public class Consola {
    
    Scanner scanner = new Scanner(System.in);
    public static void main(String[] args) {
        Consola consola = new Consola();
        consola.ejecutarMenu();  
    }

    public void ejecutarMenu() {

        int opcion = 0;
        System.out.println("1. Generar llaves");
        System.out.println("2. Ejecutar delegados");
        System.out.println("3. Salir");
        System.out.println("Ingrese una opción: ");
        opcion = scanner.nextInt();
        switch (opcion) {
            case 1:
                generarLlaves();
                break;
            case 2:
                int numClientes = 0;
                System.out.println("Ingrese el número de clientes: ");
                numClientes = scanner.nextInt();
                ejecutarDelegados(numClientes);
                break;
            case 3:
                System.out.println("Saliendo...");
                break;
            default:
                System.out.println("Opción no válida. Intente de nuevo.");
                ejecutarMenu();
                break;
            }
            scanner.close();
    }

    public void generarLlaves() {
        new KeyGenerator();
    }

    public void ejecutarDelegados(int numClientes) {
        int port = 5000;

        Servidor servidor = new Servidor(port, numClientes);
        System.out.println("numClientes: " + numClientes);
        if (numClientes == 1) {
            servidor.llenarPaquetes(Servidor.paquetes, numClientes, 32);
        } else {
            servidor.llenarPaquetes(Servidor.paquetes, numClientes, numClientes*3);
        }
        servidor.start();

        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        boolean iterativo = false;
        if (numClientes == 1) {
            iterativo = true;
        }

        for (int i = 0; i < numClientes; i++) {
            Cliente cliente = new Cliente("localhost", port, "Cliente" + i, iterativo );
            cliente.start();
        }
    }

}
