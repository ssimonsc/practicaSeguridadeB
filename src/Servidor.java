import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;

public class Servidor extends Thread {
    private static SSLServerSocket meuServerSocket;
    private static Socket cliente;
    private static String path = "/home/ssimonsc/universidade/seguridade/servidor/";
    private static String nosoKeyStore = "Keys/serverKey.jce";
    private static String nosoTrustStore = "Keys/serverTrustStore.jce";
    private static String nosoContrasinal = "nosoContrasinal";
    private static int idRexistro = 0;
    private static HashMap<Integer, Documentos> listaDocsPublicos = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsPrivados = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsXeral = new HashMap<Integer, Documentos>();

    public Servidor() {
        try {
            meuServerSocket = establecerSocket(8000);
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

        System.setProperty("javax.net.ssl.keyStore",         path + nosoContrasinal);
        System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", nosoContrasinal);

        // Almacen de confianza

        System.setProperty("javax.net.ssl.trustStore",          path + nosoTrustStore);
        System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", nosoContrasinal);
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
                            if(!verificarPeticion(peticion)) {
                                break;
                            }
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
            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
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

    public static boolean verificarPeticion(Peticion peticion) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[] arquivo = peticion.getArquivo();
        byte[] firma = peticion.getFirma();
        String certFirma = peticion.getCertFirma();

        /* Verificamos a firma */

        String algoritmo = "SHA1withRSA";

        System.out.println(certFirma);

        if(!certFirma.equalsIgnoreCase(obterNomeCertificado())) {
            System.out.println("A firma non pertence ao Cliente. Desbotando peticion...");
            return false;
        }

        // Obtener la clave publica do trustStore

        KeyStore ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(path + nosoTrustStore), nosoContrasinal.toCharArray());

        /*******************************************************************
         *                   Verificacion
         ******************************************************************/

        System.out.println("***      Verificando:         *** ");

        // Obter a clave publica do trustStore
        PublicKey clavePublicaCliente = ks.getCertificate("clientekey").getPublicKey();

        System.out.println("*** CLAVE PUBLICA DO CLIENTE ***");
        System.out.println(clavePublicaCliente);

        // Creamos un objeto para verificar
        Signature verifier = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para verificar

        verifier.initVerify(clavePublicaCliente);
        verifier.update(arquivo);

        boolean resultado = false;
        // Verificamos & resultado

        resultado = verifier.verify(firma);

        if (resultado == true)
            System.out.println("Firma CORRECTA");
        else {
            System.out.println("Firma NON correcta");
        }

        return resultado;
    }

    private static String obterNomeCertificado() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        String full_name = null;
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(path + nosoTrustStore), nosoContrasinal.toCharArray());

        Enumeration<String> enumeration = keystore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            java.security.cert.X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);

            System.out.println ("CERTIFICADO: " +
                    "\n -- Algoritmo Firma .... = " + certificate.getSigAlgName() +
                    "\n -- Usuario ............ = " + certificate.getIssuerDN() +
                    "\n -- Parametros Algoritmo = " + certificate.getSigAlgParams() +
                    "\n -- Algoritmo de la PK.. = " + certificate.getPublicKey().getAlgorithm() +
                    "\n -- Formato  ........... = " + certificate.getPublicKey().getFormat() +
                    "\n -- Codificacion ....... = " + certificate.getPublicKey().getEncoded()
            );

            full_name = certificate.getSubjectX500Principal().getName();
            System.out.println(full_name);

        }
        return full_name;
    }


    public static void rexistrar(Peticion peticion) throws IOException {
        File arquivo = new File(path + "docs/" + peticion.getNomeArquivo());
        FileOutputStream fos = new FileOutputStream(arquivo);
        fos.write(peticion.getArquivo());
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
