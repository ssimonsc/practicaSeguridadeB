import java.io.Serializable;
import java.util.Date;
import java.util.GregorianCalendar;

public class Documentos implements Serializable {
    private int idRexistro;
    private String idPropietario;
    private String nomeArquivo;
    private Date seloTemporal;
    private boolean tipoConfidencialidade;

    public Documentos(int idRexistro, String idPropietario, String nomeArquivo, Date seloTemporal, boolean tipoConfidencialidade) {
        this.idRexistro = idRexistro;
        this.idPropietario = idPropietario;
        this.nomeArquivo = nomeArquivo;
        this.seloTemporal = seloTemporal;
        this.tipoConfidencialidade = tipoConfidencialidade;
    }

    public int getIdRexistro() {
        return this.idRexistro;
    }

    public String getIdPropietario() {

        return this.idPropietario;
    }

    public String getNomeArquivo() {

        return this.nomeArquivo;
    }

    public Date getSeloTemporal() {
        return seloTemporal;
    }

    public boolean getTipoConfidencialidade() {

        return this.tipoConfidencialidade;
    }
}
