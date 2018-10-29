import java.io.Serializable;
import java.util.HashMap;

public class Resposta implements Serializable {
    private String nomeArquivo;
    private byte[] arquivo;
    private byte[] firma;
    private HashMap<Integer, Documentos> listaDocs;

    public Resposta(String nomeArquivo, byte[] arquivo, byte[] firma) {
        this.nomeArquivo = nomeArquivo;
        this.arquivo = arquivo;
        this.firma = firma;
    }

    public Resposta(HashMap<Integer, Documentos> listaDocs) {
        this.listaDocs = listaDocs;
    }

    public String getNomeArquivo() {
        return this.nomeArquivo;
    }

    public byte[] getArquivo() {
        return this.arquivo;
    }

    public HashMap<Integer, Documentos> getListaDocs() {
        return this.listaDocs;
    }
}
