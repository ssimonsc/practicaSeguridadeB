import java.io.Serializable;

public class Peticion  implements Serializable{
    private String tipoPeticion;
    private String nomeArquivo;
    private byte[] arquivo;
    private boolean tipoConfidencial;
    private byte[] firma;
    private String certFirma;
    private int idRexistro;

    public Peticion(String nomeArquivo, byte[] arquivo, boolean tipoConfidencial, byte[] firma, String certFirma){
        this.tipoPeticion = "REXISTRAR";
        this.nomeArquivo = nomeArquivo;
        this.arquivo = arquivo;
        this.tipoConfidencial= tipoConfidencial;
        this.firma = firma;
        this.certFirma = certFirma;
    }

    public Peticion(boolean tipoConfidencial, String certFirma) {
        this.tipoPeticion = "LISTAR";
        this.tipoConfidencial = tipoConfidencial;
        this.certFirma = certFirma;
    }

    public Peticion(String certFirma, int idRexistro){
        this.tipoPeticion = "RECUPERAR";
        this.certFirma = certFirma;
        this.idRexistro = idRexistro;
    }

    public Peticion() {
        this.tipoPeticion = "SAIR";
    }

    public String getTipoPeticion(){
        return this.tipoPeticion;
    }

    public String getNomeArquivo(){
        return this.nomeArquivo;
    }

    public byte[] getArquivo() {
        return this.arquivo;
    }

    public boolean getTipoConfifencial() {
        return this.tipoConfidencial;
    }

    public byte[] getFirma() {
        return firma;
    }

    public String getCertFirma() {
        return certFirma;
    }

    public int getIdRexistro() {
        return this.idRexistro;
    }

    public void setArquivo(byte[] arquivo) {
        this.arquivo = arquivo;
    }
}
