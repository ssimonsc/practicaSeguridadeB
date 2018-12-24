import java.io.Serializable;
import java.util.GregorianCalendar;

public class DocumentoAlmacenado implements Serializable {
    private byte[] firma;
    private int idRexistro;
    private byte[] seloTemporal;
    private byte[] arquivo;
    private String nome;

    public DocumentoAlmacenado(String nome, byte[] arquivo, byte[] firma, int idRexistro, byte[] seloTemporal) {
        this.nome = nome;
        this.arquivo = arquivo;
        this.firma = firma;
        this.idRexistro = idRexistro;
        this.seloTemporal = seloTemporal;
    }

    public String getNome() {
        return nome;
    }

    public byte[] getArquivo() {
        return arquivo;
    }

    public byte[] getFirma() {
        return firma;
    }

    public byte[] getSeloTemporal() {
        return seloTemporal;
    }

    public int getIdRexistro() {
        return idRexistro;
    }
}
