import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.HashMap;
import javax.security.cert.X509Certificate;

public class Servidor extends Thread {
    private static SSLServerSocket meuServerSocket;
    private static Socket cliente;
    private static String path = "/home/ssimonsc/universidade/seguridade/servidor/";
    private static int idRexistro = 0;
    private static HashMap<Integer, Documentos> listaDocsPublicos = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsPrivados = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsXeral = new HashMap<Integer, Documentos>();

    public Servidor() {
        try {
            meuServerSocket = establecerSocket(3030);
            meuServerSocket.setNeedClientAuth(true);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void main(String args[]){
        try {
            definirKeyStores();

            Servidor meuServidor = new Servidor();
            meuServidor.start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /******************************************************
                    definirKeyStores()
     *******************************************************/
    private static void definirKeyStores()
    {
        // Almacen de claves

        System.setProperty("javax.net.ssl.keyStore",         path + "Keys/serverKey.jce");
        System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", "nosoContrasinal");

        // Almacen de confianza

        System.setProperty("javax.net.ssl.trustStore",          path + "Keys/serverTrustStore.jce");
        System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "nosoContrasinal");
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

    public static SSLServerSocket establecerSocket(int porto) throws IOException {
        SSLServerSocketFactory ssf =  obterServerSocketFactory("TLS");
        return (SSLServerSocket) ssf.createServerSocket(porto);
    }

    /******************************************************
     obterServerSocketFactory(String type) {}
     *****************************************************/
    private static SSLServerSocketFactory obterServerSocketFactory(String type) {

            SSLServerSocketFactory ssf = null;

            try {

                // Estabelecer o keymanager para a autenticacion do servidor

                SSLContext ctx;
                KeyManagerFactory kmf;
                KeyStore ks;
                char[] contrasinal = "nosoContrasinal".toCharArray();

                ctx = SSLContext.getInstance("TLS");
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

                ks  = KeyStore.getInstance("JCEKS");
                ks.load(new FileInputStream(path + "Keys/serverKey.jce"), contrasinal);

                kmf.init(ks, contrasinal);

                ctx.init(kmf.getKeyManagers(), null, null);

                ssf = ctx.getServerSocketFactory();

            }
            catch (Exception e) {

                e.printStackTrace();

            }

            return ssf;
    }


    public static Peticion procesarPeticion(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in);
        Peticion peticion = (Peticion) ois.readObject();
        return (peticion);
    }

    public static void rexistrar(Peticion peticion) throws IOException {
        File arquivo = new File(path + "docs/" + peticion.getNomeArquivo());
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

        arquivo = procesarArquivo(path + "docs/" + nome);

        Resposta minhaResposta = new Resposta(nome, arquivo, firma);
        enviarResposta(minhaResposta);
    }

    public static byte[] procesarArquivo(String path) throws IOException {
        File arquivo = new File(path + "docs/");
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
