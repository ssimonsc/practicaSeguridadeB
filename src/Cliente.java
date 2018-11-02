import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Scanner;

public class Cliente {
    private static SSLSocket meuSocket;
    private static String pathCliente = "/home/ssimonsc/universidade/seguridade/cliente/";

    public static void main(String[] args) {
        int opcion = 5;
        try {

            definirKeyStores();

           // Servidor meuServidor = new Servidor();
           // meuServidor.start();
            meuSocket = establecerSocket("localhost", 3030);
            configurarSocketSSL();

//            System.out.println ("CypherSuites");
//            SSLContext context = SSLContext.getDefault();
//            SSLSocketFactory sf = context.getSocketFactory();
//            String[] cipherSuites = sf.getSupportedCipherSuites();
//            for (int i=0; i<cipherSuites.length; i++)
//                System.out.println (cipherSuites[i]);


            System.out.println ("Comeza SSL Handshake");
            meuSocket.startHandshake();
            System.out.println ("Fin SSL Handshake");

            while (opcion !=0){
                opcion = imprimirMenu();
                elexirFuncion(opcion);
            }
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

        System.setProperty("javax.net.ssl.keyStore",         pathCliente + "Keys/clienteKey.jce");
        System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", "nosoContrasinal");

        // Almacen de confianza

        System.setProperty("javax.net.ssl.trustStore",          pathCliente + "Keys/clientTrustStore.jce");
        System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "nosoContrasinal");
    }

    public static SSLSocket establecerSocket(String host, int porto) throws  IOException {
        SSLSocketFactory clienteFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        return (SSLSocket) clienteFactory.createSocket(host, porto);
    }

    public static void configurarSocketSSL() throws IOException {
        String[] enabled = meuSocket.getEnabledCipherSuites();
        HashMap<Integer, String> selec = new HashMap<Integer, String>();
        for (int i = 0; i < enabled.length; i++) {
            System.out.println(i + "->" + enabled[i]);
            selec.put(i, enabled[i]);
        }

        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
//        Integer seleccion = Integer.parseInt(teclado.readLine());
//
//        String[] CipherSuite = new String[enabled.length + 1];
//        CipherSuite[0] = selec.get(seleccion);
//        System.out.println("Seleccionaches:  " + CipherSuite[0] + "\nDaraselle a maior prioridade posíbel.");
//        // Cambiamos a prioridade de dito algoritmo para ser o de mais prioridade
//        for (int i = 0; i < CipherSuite.length - 1; i++)
//            CipherSuite[i + 1] = enabled[i];


        String[]   cipherSuitesHabilitadas = {"TLS_RSA_WITH_AES_128_CBC_SHA"};
        meuSocket.setEnabledCipherSuites(cipherSuitesHabilitadas);

        SSLParameters params = meuSocket.getSSLParameters();
        System.out.println("Desexa autentificacion do cliente?(si/non)");
        if (teclado.readLine().equals("si"))
            meuSocket.getSSLParameters().setNeedClientAuth(true);
        else
            meuSocket.getSSLParameters().setNeedClientAuth(false);
        meuSocket.setSSLParameters(params);
    }

    public static int imprimirMenu() {
        int opcion;
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n\n******* Benvido ao servizo de rexistro seguro de documentos *******");
        System.out.println("\n\nElixa unha das seguintes opcións: ");
        while(true) {
            System.out.println("\n\n\t1. Rexistrar documento \n\t2. Recuperar documento \n\t3. Listar documentos \n\t0. Salir");
            String entrada = scanner.nextLine();
            if (entrada.equals("1") || entrada.equals("2") || entrada.equals("3") || entrada.equals("0")) {
                opcion = Integer.parseInt(entrada);
            } else {
                System.out.println("\n\nOpción non válida porfavor elixa unha das opcións mostradas no menu");
                continue;
            }
            return opcion;
        }
    }

    public static void elexirFuncion(int opcion) throws IOException, ClassNotFoundException {
        switch (opcion) {
            case 1: rexistrarDocumento();
            break;

            case 2: recuperarDocumento();
            break;

            case 3: listarDocumentos();
            break;

            case 0: sair();
            break;
        }
    }

    public static void rexistrarDocumento() throws IOException {
        byte[] arquivo;
        String nomeArquivo;
        boolean tipoConfidencialidade = false;
        byte[] firma = new byte[2000];

        Scanner scanner = new Scanner(System.in);

        System.out.println("\n\nIntroduza o path do ficheiro a rexistrar\n");
        String path = scanner.nextLine();
        arquivo = procesarArquivo(path);


        System.out.println("\n\nIntroduza o nome do ficheiro a rexistrar\n");
        nomeArquivo = scanner.nextLine();

        while(true) {
            System.out.println("\n\nQuere que o arquivo sexa privado? (si/non)\n");
            String privado = scanner.nextLine();
            if(!privado.equalsIgnoreCase("si") && !privado.equalsIgnoreCase("non"))
                continue;

            if(privado.equalsIgnoreCase("si"))
                tipoConfidencialidade = true;

            break;
        }

        Peticion minhaPeticion = new Peticion(nomeArquivo, arquivo, tipoConfidencialidade, firma);
        enviarPeticion(minhaPeticion);
    }

    public static void listarDocumentos() throws IOException, ClassNotFoundException {
        boolean tipoConfidencialidade;

        Scanner scanner = new Scanner(System.in);

        System.out.println("\n\nIntroduza o tipo de ficheiros a listar (PUBLICOS/PRIVADOS)\n");
        while(true) {
            String tipo = scanner.nextLine();
            if (tipo.equalsIgnoreCase("PUBLICOS")) {
                tipoConfidencialidade = false;
                break;
            } else if (tipo.equalsIgnoreCase("PRIVADOS")) {
                tipoConfidencialidade = true;
                break;
            } else
                System.out.println("Tipo non válido");
        }

        Peticion minhaPeticion = new Peticion(tipoConfidencialidade);
        enviarPeticion(minhaPeticion);
        InputStream in = meuSocket.getInputStream();
        Resposta resposta = procesarResposta(in);
        System.out.println("resposta recibida");

        HashMap<Integer, Documentos> listaDoc = resposta.getListaDocs();
        Iterator it = listaDoc.keySet().iterator();
        while(it.hasNext()){
            Integer key = (Integer) it.next();
            Documentos doc = listaDoc.get(key);
            System.out.println("ID do rexistro: " + doc.getIdRexistro() + " | Id do propietario: " + doc.getIdPropietario() + " | Nome do Arquivo: " + doc.getNomeArquivo());
        }

    }

    public static void recuperarDocumento() throws IOException, ClassNotFoundException {
        int idRexistro;
        Scanner scanner = new Scanner(System.in);

        System.out.println("\n\nIntroduza o id de rexistro do ficheiro a recuperar\n");
        idRexistro = Integer.parseInt(scanner.nextLine());

        Peticion minhaPeticion = new Peticion(idRexistro);
        enviarPeticion(minhaPeticion);
        InputStream in = meuSocket.getInputStream();
        Resposta resposta = procesarResposta(in);
        System.out.println("resposta recibida");

        File arquivo = new File(pathCliente + resposta.getNomeArquivo());
        FileOutputStream fos = new FileOutputStream(arquivo);
        fos.write(resposta.getArquivo());
        fos.close();

    }

    public static void sair() throws IOException {
        Peticion minhaPeticion = new Peticion();
        enviarPeticion(minhaPeticion);
    }

    public static byte[] procesarArquivo(String path) throws IOException {
        File arquivo = new File(path);
        byte[] arquivoByte = new byte[(int) arquivo.length()];
        FileInputStream FiS = new FileInputStream(arquivo);
        FiS.read(arquivoByte);
        FiS.close();

        return  arquivoByte;
    }

    public static void  enviarPeticion(Peticion minhaPeticion) throws IOException {
        OutputStream out = meuSocket.getOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(minhaPeticion);
    }

    public static Resposta procesarResposta(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in);
        Resposta resposta = (Resposta) ois.readObject();
        return (resposta);
    }
}
