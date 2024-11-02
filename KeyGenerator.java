import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.FileOutputStream;
import java.io.IOException;

public class KeyGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public KeyGenerator() {
        generarLlaves();
    }

    public void generarLlaves() {
        try {
            // Paso 1: Generar el par de llaves
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024); // Llave de 1024 bits
            KeyPair keyPair = keyGen.generateKeyPair();
            
            // Llaves generadas
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            
            // Paso 2: Guardar la llave pública en un archivo
            try (FileOutputStream fos = new FileOutputStream("public/public.key")) {
                fos.write(publicKey.getEncoded());
            }
            System.out.println("Llave pública guardada en public.key");

            // Paso 3: Guardar la llave privada en un archivo
            try (FileOutputStream fos = new FileOutputStream("server/private.key")) {
                fos.write(privateKey.getEncoded());
            }
            System.out.println("Llave privada guardada en private.key");

            // Nota: En un entorno real, configura los permisos de archivo aquí si es posible

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: Algoritmo RSA no disponible.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Error al guardar las llaves en archivos.");
            e.printStackTrace();
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}
