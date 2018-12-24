import java.io.Serializable;
import java.util.GregorianCalendar;
import java.util.HashMap;

public class Resposta implements Serializable {
    private int idResposta;
    private int idRexistro;
    private byte[] seloTemporal;
    private byte[] firma;
    private String certFirma;
    private String nomeArquivo;
    private byte[] arquivo;
    private HashMap<Integer, Documentos> listaDocs;
    private boolean tipoConfidencial;

    public Resposta(int idResposta) {
        this.idResposta = idResposta;
    }

    public Resposta(int idResposta, int idRexistro, byte[] seloTemporal, byte[] firma, String certFirma) {
        this.idResposta = idResposta;
        this.idRexistro = idRexistro;
        this.seloTemporal = seloTemporal;
        this.firma = firma;
        this.certFirma = certFirma;
    }

    public Resposta(String nomeArquivo, byte[] arquivo, byte[] firma) {
        this.nomeArquivo = nomeArquivo;
        this.arquivo = arquivo;
        this.firma = firma;
    }

    public Resposta(int idResposta, boolean tipoConfidencial, int idRexistro, byte[] seloTemporal, byte[] arquivo, byte[] firma, String certFirma) {
        this.idResposta = idResposta;
        this.tipoConfidencial = tipoConfidencial;
        this.idRexistro = idRexistro;
        this.seloTemporal = seloTemporal;
        this.arquivo = arquivo;
        this.firma = firma;
        this.certFirma = certFirma;
    }

    public Resposta(HashMap<Integer, Documentos> listaDocs) {
        this.listaDocs = listaDocs;
    }

    public int getIdResposta() {
        return idResposta;
    }

    public int getIdRexistro() {
        return idRexistro;
    }

    public byte[] getSeloTemporal() {
        return seloTemporal;
    }

    public byte[] getFirma() {
        return firma;
    }

    public String getCertFirma() {
        return certFirma;
    }

    public String getNomeArquivo() {
        return this.nomeArquivo;
    }

    public byte[] getArquivo() {

        return this.arquivo;
    }

    public boolean isTipoConfidencial() {
        return tipoConfidencial;
    }

    public void setNomeArquivo(String nomeArquivo) {
        this.nomeArquivo = nomeArquivo;
    }

    public HashMap<Integer, Documentos> getListaDocs() {

        return this.listaDocs;
    }
}
