import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

public class Servidor extends Thread {
    private static ServerSocket meuServerSocket;
    private static Socket cliente;
    private static String path = "/home/ssimonsc/universidade/seguridade/servidor/docs/";
    private static int idRexistro = 0;
    private static HashMap<Integer, Documentos> listaDocsPublicos = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsPrivados = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsXeral = new HashMap<Integer, Documentos>();

    public Servidor() {
        try {
            meuServerSocket = establecerSocket(3000);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void main(String args[]){
        try {
            Servidor meuServidor = new Servidor();
            meuServidor.start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() {
        while (true) {
            try {
                cliente = meuServerSocket.accept();    // Esperamos a que un cliente mande unha petición
                System.out.println("Cliente conectado\n\t");
                InputStream in = cliente.getInputStream();
                OutputStream out = cliente.getOutputStream();
                String tipoPeticion = "";
                while (!tipoPeticion.equalsIgnoreCase("SAIR")) {
                    Peticion peticion = procesarPeticion(in);

                    tipoPeticion = peticion.getTipoPeticion();
                    System.out.println("peticion recibida " + tipoPeticion);
                    switch (tipoPeticion) {
                        case "REXISTRAR":
                            rexistrar(peticion);
                            break;

                        case "RECUPERAR":
                            recuperar(peticion);
                            break;

                        case "LISTAR":
                            listar(peticion);
                            break;

                        case "SAIR": break;

                        default:
                            System.out.println("Petición non válida");
                            break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    public static ServerSocket establecerSocket(int porto) throws IOException {
       // ServerSocketFactory ssf = ServerSocketFactory.getDefault();
        return new ServerSocket(porto);
    }

    public static Peticion procesarPeticion(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in);
        Peticion peticion = (Peticion) ois.readObject();
        return (peticion);
    }

    public static void rexistrar(Peticion peticion) throws IOException {
        File arquivo = new File(path + peticion.getNomeArquivo());
        FileOutputStream fos = new FileOutputStream(arquivo);
        fos.write(peticion.getArquivo());
//        ObjectOutputStream oos = new ObjectOutputStream(fos);
//        oos.writeObject(peticion);
        fos.close();

        Documentos novoDocumento = new Documentos(idRexistro++, 0, peticion.getNomeArquivo(), peticion.getTipoConfifencial());
        if (peticion.getTipoConfifencial())
            listaDocsPrivados.put(novoDocumento.getIdRexistro(), novoDocumento);
        else
            listaDocsPublicos.put(novoDocumento.getIdRexistro(), novoDocumento);

        listaDocsXeral.put(novoDocumento.getIdRexistro(), novoDocumento);

    }

    public static void listar(Peticion peticion) throws IOException {
        boolean tipo = peticion.getTipoConfifencial();
        HashMap<Integer, Documentos> listaDocs;

        if(tipo)
            listaDocs = listaDocsPrivados;
        else
            listaDocs = listaDocsPublicos;

        Resposta minhaResposta = new Resposta(listaDocs);
        enviarResposta(minhaResposta);
    }

    public static void recuperar(Peticion peticion) throws IOException {
        byte[] arquivo;
        byte[] firma = new byte[2000];

        int idRex = peticion.getIdRexistro();
        String nome = listaDocsXeral.get(idRex).getNomeArquivo();

        arquivo = procesarArquivo(path + nome);

        Resposta minhaResposta = new Resposta(nome, arquivo, firma);
        enviarResposta(minhaResposta);
    }

    public static byte[] procesarArquivo(String path) throws IOException {
        File arquivo = new File(path);
        byte[] arquivoByte = new byte[(int) arquivo.length()];
        FileInputStream FiS = new FileInputStream(arquivo);
        FiS.read(arquivoByte);
        FiS.close();

        return  arquivoByte;
    }

    public static void  enviarResposta(Resposta minhaResposta) throws IOException {
        OutputStream out = cliente.getOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(minhaResposta);
    }
}
