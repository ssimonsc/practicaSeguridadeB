import java.io.Serializable;

public class Peticion  implements Serializable{
    private String tipoPeticion;
    private String nomeArquivo;
    private byte[] arquivo;
    private boolean tipoConfidencial;
    private byte[] firma;
    private int idRexistro;

    public Peticion(String nomeArquivo, byte[] arquivo, boolean tipoConfidencial, byte[] firma){
        this.tipoPeticion = "REXISTRAR";
        this.nomeArquivo = nomeArquivo;
        this.arquivo = arquivo;
        this.tipoConfidencial= tipoConfidencial;
        this.firma = firma;
    }

    public Peticion(boolean tipoConfidencial) {
        this.tipoPeticion = "LISTAR";
        this.tipoConfidencial = tipoConfidencial;
    }

    public Peticion(int idRexistro){
        this.tipoPeticion = "RECUPERAR";
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

    public int getIdRexistro() {
        return this.idRexistro;
    }
}
