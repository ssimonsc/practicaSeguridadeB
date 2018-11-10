import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Scanner;

public class Cliente {
    private static SSLSocket meuSocket;
    private static String pathCliente = "/home/ssimonsc/universidade/seguridade/cliente/";
    private static String nosoKeyStore = "Keys/clienteKey.jce";
    private static String nosoTrustStore = "Keys/clientTrustStore.jce";
    private static String nosoContrasinal = "nosoContrasinal";

    public static void main(String[] args) {
        int opcion = 5;
        try {

            definirKeyStores();

           // Servidor meuServidor = new Servidor();
           // meuServidor.start();
            meuSocket = establecerSocket("localhost", 8000);
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

        System.setProperty("javax.net.ssl.keyStore",         pathCliente + nosoKeyStore);
        System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", nosoContrasinal);

        // Almacen de confianza

        System.setProperty("javax.net.ssl.trustStore",          pathCliente + nosoTrustStore);
        System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", nosoContrasinal);
    }

    public static SSLSocket establecerSocket(String host, int porto) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        SSLContext ctx;
        KeyManagerFactory kmf;
        KeyStore ks;

        ctx = SSLContext.getInstance("TLS");
        kmf = KeyManagerFactory.getInstance("SunX509");
        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(pathCliente + nosoKeyStore), nosoContrasinal.toCharArray());
        kmf.init(ks, nosoContrasinal.toCharArray());
        ctx.init(kmf.getKeyManagers(), null, null);

        SSLSocketFactory clienteFactory = ctx.getSocketFactory();
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
    //    meuSocket.setSSLParameters(params);
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

    public static void elexirFuncion(int opcion) throws Exception {
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

    public static void rexistrarDocumento() throws Exception {
        File arquivo;
        byte[] arquivoByte;
        byte[] arquivoCifrado;
        String nomeArquivo;
        boolean tipoConfidencialidade = false;
        byte[] firma;
        String certFirma;
        Peticion minhaPeticion;

        Scanner scanner = new Scanner(System.in);

        arquivo = new File(mostrarArquivosCliente());
        if(arquivo == null ) {
            return;
        }
        arquivoByte = procesarArquivo(arquivo.getAbsolutePath());

        System.out.println("\n\nIntroduza o nome co que quere rexistrar o ficheiro\n");
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

        /* Firmamos o documento */
        firma = firmador(arquivo.getAbsolutePath());

        /* Obtemos o certificado de firma */
        certFirma = obterNomeCertificado();

        /* Ciframos o documento  Ainda non funciona*/
        if(tipoConfidencialidade) {
            arquivoCifrado = cifrador(arquivoByte);
             minhaPeticion = new Peticion(nomeArquivo, arquivoCifrado, tipoConfidencialidade, firma, certFirma);
//            minhaPeticion = new Peticion(nomeArquivo, arquivoByte, tipoConfidencialidade, firma, certFirma);

        }
        else
         minhaPeticion = new Peticion(nomeArquivo, arquivoByte, tipoConfidencialidade, firma, certFirma);

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

    private static String mostrarArquivosCliente() {
        System.out.println("**** BENVIDO AO SEU CARTAFOL PERSOAL DE DOCUMENTOS ****");
        HashMap<Integer, String> ficheiros = new HashMap<Integer, String>();
        Scanner teclado = new Scanner(System.in);
        File cartafol = new File(pathCliente + "docsCliente/");
        int i = 1;
        if (cartafol.listFiles().length == 0) {
            System.out.println("\nNon ten documentos dispoñibeis");
            return null;
        }
        for (final File fileEntry : cartafol.listFiles()) {
            System.out.println("\nDocumentos dispoñibeis para o rexistro:");
            ficheiros.put(i, fileEntry.getAbsolutePath());
            System.out.println("\n\n" + i++ + "->" + fileEntry.getName());
            System.out.println("\nElixa o documento desexado para o rexistro, seleccionando o número");
        }
        int seleccion = Integer.parseInt(teclado.nextLine());
        if (ficheiros.containsKey(seleccion))
            return ficheiros.get(seleccion);
        else
            return null;

    }

    public static byte[] procesarArquivo(String path) throws IOException {
        File arquivo = new File(path);
        byte[] arquivoByte = new byte[(int) arquivo.length()];
        FileInputStream FiS = new FileInputStream(arquivo);
        FiS.read(arquivoByte);
        FiS.close();

        return  arquivoByte;
    }

    private static byte[] firmador(String path) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, InvalidKeyException, SignatureException, UnrecoverableEntryException {

        FileInputStream arquivo = new FileInputStream(path);

        String 		algoritmo        = "SHA1withRSA";
        int    		longbloque;
        byte   		bloque[]         = new byte[1024];
        long   		filesize         = 0;

        // Variables para el KeyStore

        KeyStore    ks;
        char[]      ks_password  	= nosoContrasinal.toCharArray();
        char[]      key_password 	= nosoContrasinal.toCharArray();
        String		entry_alias		= "clientekey";

        System.out.println("******************************************* ");
        System.out.println("*               FIRMA                     * ");
        System.out.println("******************************************* ");

        // Obter a clave privada do keystore

        ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(pathCliente + nosoKeyStore),  ks_password);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                ks.getEntry(entry_alias,
                        new KeyStore.PasswordProtection(key_password));

        PrivateKey privateKey = pkEntry.getPrivateKey();

        // Visualizar clave privada

        System.out.println("*** CLAVE PRIVADA ***");
        System.out.println("Algoritmo de Firma (sen o Hash): " + privateKey.getAlgorithm());
        System.out.println(privateKey);

        // Creamos un obxeto para firmar

        Signature signer = Signature.getInstance(algoritmo);

        // Inicializamos o obxeto para firmar
        signer.initSign(privateKey);

        // Para firmar primeiro pasamos o hash á mensaxe (metodo "update")
        // e despois firmamos o hash (metodo sign).

        byte[] firma = null;

        while ((longbloque = arquivo.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            signer.update(bloque, 0, longbloque);
        }

        firma = signer.sign();

        arquivo.close();

        return firma;
    }

    private static String obterNomeCertificado() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        String full_name = null;
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(pathCliente + nosoKeyStore), nosoContrasinal.toCharArray());

        Enumeration<String> enumeration = keystore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);

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
            String[] splat = full_name.split(",");
            for (String element : splat) {
                if (element.startsWith("OU") || element.startsWith("O")) {
                    full_name = element.substring(2, element.length() - 1);
                }
            }
            break;

        }
        System.out.println(full_name);
        return full_name;
    }

    private static byte[] cifrador(byte[] archivo) throws Exception {
        String provider = "SunJCE";
        String algoritmo = "RSA";
        String transformacion = "/ECB/PKCS1Padding";

        /************************************************************
         * Xerar e almacear a clave
         ************************************************************/

        // Obtener la clave publica do trustStore

        KeyStore ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(pathCliente + nosoTrustStore), nosoContrasinal.toCharArray());

        // Obter a clave publica do trustStore
        PublicKey clavePublicaServidor = ks.getCertificate("serverkey").getPublicKey();

        System.out.println("*** CLAVE PUBLICA DO CLIENTE ***");
        System.out.println(clavePublicaServidor);

        /************************************************************
                                     CIFRAR
         ************************************************************/
        Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
        // Cifrase coa modalidade opaca da clave
        cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaServidor);

        // int longbloque;
        byte[] bloquecifrado = cifrador.update(archivo);

        // Devolvemos el fichero cifrado
        return bloquecifrado;

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
