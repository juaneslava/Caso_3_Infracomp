package logica;

public class Paquete {

    private String id;
    private String id_cliente;
    private int estado;

    public Paquete(String id, String id_cliente, int estado) {
        this.id = id;
        this.id_cliente = id_cliente;
        this.estado = estado;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId_cliente() {
        return id_cliente;
    }

    public void setId_cliente(String id_cliente) {
        this.id_cliente = id_cliente;
    }

    public int getEstado() {
        return estado;
    }

    public void setEstado(int estado) {
        this.estado = estado;
    }

    

}
