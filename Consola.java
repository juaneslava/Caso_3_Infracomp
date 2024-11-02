import java.util.Scanner;

public class Consola {

    public static void main(String[] args) {
        Consola consola = new Consola();
        consola.ejecutarMenu();  
    }

    public void ejecutarMenu() {

        int opcion = 0;
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. Generar llaves");
        System.out.println("2. Ejecutar delegados");
        System.out.println("3. Salir");
        System.out.println("Ingrese una opción: ");
        opcion = scanner.nextInt();
        switch (opcion) {
            case 1:
                System.out.println("Generando llaves...");
                KeyGenerator keyGen = generarLlaves();
                System.out.println("Llaves publica: " + keyGen.getPublicKey());
                System.out.println("Llaves privada: " + keyGen.getPrivateKey());
                ejecutarMenu();
                break;
            case 2:
                System.out.println("Ejecutando delegados...");
                // Lógica para ejecutar delegados
                ejecutarMenu();
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

}
