import java.io.Serializable;

public class Documentos implements Serializable {
    private int idRexistro;
    private int idPropietario;
    private String nomeArquivo;
    private boolean tipoConfidencialidade;

    public Documentos(int idRexistro, int idPropietario, String nomeArquivo, boolean tipoConfidencialidade) {
        this.idRexistro = idRexistro;
        this.idPropietario = idPropietario;
        this.nomeArquivo = nomeArquivo;
        this.tipoConfidencialidade = tipoConfidencialidade;
    }

    public int getIdRexistro() {
        return this.idRexistro;
    }

    public int getIdPropietario() {
        return this.idPropietario;
    }

    public String getNomeArquivo() {
        return this.nomeArquivo;
    }

    public boolean getTipoConfidencialidade() {
        return this.tipoConfidencialidade;
    }
}
