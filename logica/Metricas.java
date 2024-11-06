package logica;

import java.io.FileWriter;
import java.io.IOException;

public class Metricas {
    // Para almacenar los tiempos medidos
    private long tiempoReto = 0;
    private long tiempoGeneracionParametros = 0;
    private long tiempoVerificacionConsulta = 0;

    // Métodos para guardar los tiempos
    public void setTiempoReto(long inicio, long fin) {
        tiempoReto += (fin - inicio);
    }

    public void setTiempoGeneracionParametros(long inicio, long fin) {
        tiempoGeneracionParametros += (fin - inicio);
    }

    public void setTiempoVerificacionConsulta(long inicio, long fin) {
        tiempoVerificacionConsulta += (fin - inicio);
    }

    // Escribir métricas a archivo
    public void escribirMetricas(String escenario) {
        try (FileWriter writer = new FileWriter("metricas_" + escenario + ".txt", true)) {
            writer.write("Tiempo de respuesta al reto: " + tiempoReto + " ms\n");
            writer.write("Tiempo de generación de G, P, Gx: " + tiempoGeneracionParametros + " ms\n");
            writer.write("Tiempo de verificación de la consulta: " + tiempoVerificacionConsulta + " ms\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
