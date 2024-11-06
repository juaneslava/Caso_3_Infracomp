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
                KeyGenerator keyGen = generarLlaves();
                break;
            case 2:
                ejecutarDelegados();
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

    public KeyGenerator generarLlaves() {
        KeyGenerator keyGenerator = new KeyGenerator();
        return keyGenerator;
    }

    public void ejecutarDelegados() {
        int port = 5000;

        Servidor servidor = new Servidor(port);
        servidor.start();

        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Cliente cliente = new Cliente("localhost", port);
        cliente.start();
    }

}
