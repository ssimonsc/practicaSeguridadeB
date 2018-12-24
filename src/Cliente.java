import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import javax.print.DocFlavor;
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
    private static String nosoKeyStore = "almacenes/cliente/client1.jce";
    private static String nosoTrustStore = "almacenes/truestore_compartido/truestore.jce";
    private static String nosoContrasinalKS = "passclient1";
    private static String nosoContrasinalTS = "passcacerts";

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
        System.setProperty("javax.net.ssl.keyStorePassword", nosoContrasinalKS);

        // Almacen de confianza

        System.setProperty("javax.net.ssl.trustStore",          pathCliente + nosoTrustStore);
        System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", nosoContrasinalTS);
    }

    public static SSLSocket establecerSocket(String host, int porto) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        SSLContext ctx;
        KeyManagerFactory kmf;
        KeyStore ks;

        ctx = SSLContext.getInstance("TLS");
        kmf = KeyManagerFactory.getInstance("SunX509");
        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(pathCliente + nosoKeyStore), nosoContrasinalKS.toCharArray());
        kmf.init(ks, nosoContrasinalKS.toCharArray());
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
        byte[] firmaCliente;
        String certFirma;
        Peticion minhaPeticion;

        Scanner scanner = new Scanner(System.in);

        arquivo = new File(mostrarArquivosCliente());
        if(arquivo == null ) {
            return;
        }

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

        /* Obtemos o certificado de firma */
        certFirma = obterNomeCertificado();
        arquivoByte = procesarArquivo(arquivo.getAbsolutePath());
        firmaCliente = firmador(arquivoByte);
        /* Ciframos o documento */
        if(tipoConfidencialidade) {
            cifrador(arquivo.getAbsolutePath());
            arquivoCifrado = procesarArquivo(pathCliente + "docsCliente/" + "temporalCifrado");
            eliminarArquivo(pathCliente + "docsCliente/" + "temporalCifrado");
            minhaPeticion = new Peticion(nomeArquivo, arquivoCifrado, tipoConfidencialidade, firmaCliente, certFirma);
        }
        else minhaPeticion = new Peticion(nomeArquivo, arquivoByte, tipoConfidencialidade, firmaCliente, certFirma);


        enviarPeticion(minhaPeticion);

        Resposta resposta = procesarResposta(meuSocket.getInputStream());
        switch (resposta.getIdResposta()) {
            case 0: if(verificarResposta(resposta, minhaPeticion, arquivoByte)) eliminarArquivo(arquivo.getAbsolutePath());
                break;

            case -1: System.out.println("O seu certificado de firma non se atopa no rexistro de confianza do servidor");
                break;

            case -2: System.out.println("A súa firma e incorrecta");
        }
    }

    public static void listarDocumentos() throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        boolean tipoConfidencialidade;

        Scanner scanner = new Scanner(System.in);

        System.out.println("\n\nIntroduza o tipo de ficheiros a listar (PUBLICOS/PRIVADOS)\n");
        while(true) {
            String tipo = scanner.nextLine();
            if (tipo.toLowerCase().equalsIgnoreCase("publicos")) {
                tipoConfidencialidade = false;
                break;
            } else if (tipo.toLowerCase().equalsIgnoreCase("privados")) {
                tipoConfidencialidade = true;
                break;
            } else
                System.out.println("Tipo non válido");
        }
        String certFirma = obterNomeCertificado();
        Peticion minhaPeticion = new Peticion(tipoConfidencialidade, certFirma);
        enviarPeticion(minhaPeticion);
        InputStream in = meuSocket.getInputStream();
        Resposta resposta = procesarResposta(in);
        System.out.println("resposta recibida");

        HashMap<Integer, Documentos> listaDoc = resposta.getListaDocs();
        Iterator it = listaDoc.keySet().iterator();
        if (tipoConfidencialidade) System.out.println("Lista de documentos privados:\n\n");
        else System.out.println("Lista de documentos públicos:\n\n");

        while(it.hasNext()){
            Integer key = (Integer) it.next();
            Documentos doc = listaDoc.get(key);
            System.out.println("ID do rexistro: " + doc.getIdRexistro()+ " | Nome do Arquivo: " + doc.getNomeArquivo() + " | Id do propietario: " + doc.getIdPropietario() + " | Data de rexistro: " + doc.getSeloTemporal().toGMTString());
        }

    }

    public static void recuperarDocumento() throws Exception {
        int idRexistro;
        Scanner scanner = new Scanner(System.in);

        System.out.println("\n\nIntroduza o id de rexistro do ficheiro a recuperar\n");
        idRexistro = Integer.parseInt(scanner.nextLine());

        String certFirma = obterNomeCertificado();
        Peticion minhaPeticion = new Peticion(certFirma, idRexistro);
        enviarPeticion(minhaPeticion);
        InputStream in = meuSocket.getInputStream();
        Resposta resposta = procesarResposta(in);
        System.out.println("resposta recibida");

        if(!(comprobarCertificado(resposta.getCertFirma()))) {
            System.out.println("CERTIFICADO DE REXISTRO INCORRECTO");
            return;
        }

        if(!verificarFirma(resposta)) {
            System.out.println("FALLO DE FIRMA DO REXISTRADOR");
            return;
        }

        if(resposta.isTipoConfidencial()) {
            gardarArquivo("temporalCifrado", resposta.getArquivo());
            descifradorAsimetrico(resposta.getNomeArquivo());
            eliminarArquivo(pathCliente + "docsCliente/temporalCifrado");
        }
        else gardarArquivo(resposta.getNomeArquivo(), resposta.getArquivo());
        System.out.println("DOCUMENTO RECUPERADO CORRECTAMENTE");
    }

    private static void gardarArquivo(String nome, byte[] arquivoByte) throws IOException {
        File arquivo = new File(pathCliente + "docsCliente/" + nome);
        FileOutputStream fos = new FileOutputStream(arquivo);
        fos.write(arquivoByte);
        fos.close();
    }

    public static boolean verificarFirma(Resposta resposta) throws Exception {
        byte[] firma;
        byte[] arquivo;
        String certFirma = resposta.getCertFirma();


        /* Verificamos a firma */

        String algoritmo = "SHA1withRSA";

        System.out.println(certFirma);


        // Obtener la clave publica do trustStore

        KeyStore ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(pathCliente + nosoTrustStore), nosoContrasinalTS.toCharArray());

        /*******************************************************************
         *                   Verificacion
         ******************************************************************/

        System.out.println("***      Verificando:         *** ");

        // Obter a clave publica do trustStore
        PublicKey clavePublicaCliente = ks.getCertificate("server_cer").getPublicKey();

        System.out.println("*** CLAVE PUBLICA DO SERVIDOR ***");
        System.out.println(clavePublicaCliente);

        // Creamos un objeto para verificar
        Signature verifier = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para verificar
        byte[] datos;
        if(resposta.isTipoConfidencial()) {
            gardarArquivo("temporalCifrado", resposta.getArquivo());
            descifradorAsimetrico("temporalSenCifrar");
            arquivo = procesarArquivo(pathCliente + "docsCliente/" + "temporalSenCifrar");
            eliminarArquivo(pathCliente + "docsCliente/temporalCifrado");
            eliminarArquivo(pathCliente + "docsCliente/temporalSenCifrar");
            firma = firmador(arquivo);
        } else {
            arquivo = resposta.getArquivo();
            firma = firmador(arquivo);
        }
        datos = getDatosComprobarFirma(resposta, arquivo, firma);
        verifier.initVerify(clavePublicaCliente);

        verifier.update(datos);

        boolean resultado = false;
        // Verificamos & resultado

        resultado = verifier.verify(resposta.getFirma());
        return resultado;
    }

    public static void descifradorAsimetrico(String nome) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, CertificateException, BadPaddingException, IllegalBlockSizeException {
        String provider = "SunJCE";
        int longclave 			= 2048;               // NOTA -- Probar a subir este valor e ir viendo como
        FileInputStream  ftextocifrado2 = new FileInputStream( pathCliente + "docsCliente/" + "temporalCifrado");
        FileOutputStream ftextoclaro2 = new FileOutputStream( pathCliente + "docsCliente/" + nome);

        byte bloquecifrado2[] = new byte[longclave/8];
        byte bloqueclaro2[] = new byte[512];  // *** Buffer sobredimensionado ***

        String algoritmo 		= "RSA";
        String transformacion1 	= "/ECB/PKCS1Padding"; //Relleno de longitud fija de 88 bits (11 bytes)
        String transformacion2 	= "/ECB/OAEPPadding"; // Este relleno tiene una longitud mayor y es variable
        int longbloque;
        long t, tbi, tbf; 	    // tiempos totales y por bucle
        double lf; 				// longitud del fichero

        KeyStore    ks;
        char[]      ks_password  	= nosoContrasinalKS.toCharArray();
        char[]      key_password 	= nosoContrasinalKS.toCharArray();
        String		entry_alias		= "client1";


        // Obter a clave privada do keystore

        ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(pathCliente + nosoKeyStore),  ks_password);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                ks.getEntry(entry_alias,
                        new KeyStore.PasswordProtection(key_password));

        PrivateKey privateKey = pkEntry.getPrivateKey();


        System.out.println("\n*** INICIO DESCIFRADO " + algoritmo + "-" + longclave + " ************");

        Cipher descifrador = Cipher.getInstance(algoritmo +
                        transformacion1,
                provider);

        descifrador.init(Cipher.DECRYPT_MODE, privateKey);


        // Datos para medidas de velocidad descifrado
        t = 0; lf = 0; tbi = 0;  tbf = 0;

        while ((longbloque = ftextocifrado2.read(bloquecifrado2)) > 0) {

            lf = lf + longbloque;

            tbi = System.nanoTime();

            bloqueclaro2 = descifrador.update(bloquecifrado2, 0, longbloque);
            bloqueclaro2 = descifrador.doFinal();

            tbf = System.nanoTime();
            t = t + tbf - tbi;

            ftextoclaro2.write(bloqueclaro2);
        }


        ftextocifrado2.close();
        ftextoclaro2.close();

        // Escribir resultados medida velocidad descifrado

        System.out.println("*** FIN DESCIFRADO " + algoritmo + "-" + longclave
                + " Provider: " + provider);
        System.out.println("Bytes  descifrados = " + (int) lf);
        System.out.println("Tiempo descifrado  = " + t / 1000000 + " mseg");
        System.out.println("Velocidad = " + (lf * 8 * 1000) / t + " Mpbs");
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

    private static void eliminarArquivo(String pathArquivo) {
        File arquivo = new File(pathArquivo);
        arquivo.delete();
    }

    public static byte[] procesarArquivo(String path) throws IOException {
        File arquivo = new File(path);
        byte[] arquivoByte = new byte[(int) arquivo.length()];
        FileInputStream FiS = new FileInputStream(arquivo);
        FiS.read(arquivoByte);
        FiS.close();

        return  arquivoByte;
    }


    private static byte[] firmador(byte[] arquivo) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, InvalidKeyException, SignatureException, UnrecoverableEntryException {
        String 		algoritmo        = "SHA1withRSA";
        int    		longbloque;
        byte   		bloque[]         = new byte[1024];
        long   		filesize         = 0;
        KeyStore    ks;
        char[]      ks_password  	= nosoContrasinalKS.toCharArray();
        char[]      key_password 	= nosoContrasinalKS.toCharArray();
        String		entry_alias		= "client1";

        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(pathCliente + nosoKeyStore),  ks_password);
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                ks.getEntry(entry_alias,
                        new KeyStore.PasswordProtection(key_password));

        PrivateKey privateKey = pkEntry.getPrivateKey();
        Signature signer = Signature.getInstance(algoritmo);
        signer.initSign(privateKey);
        byte[] firma = null;
        signer.update(arquivo);
        firma = signer.sign();
        return firma;
    }

    public static boolean verificarResposta(Resposta resposta, Peticion peticion, byte[] arquivo) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, UnrecoverableEntryException, NoSuchProviderException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        byte[] firma = resposta.getFirma();
        String certFirma = resposta.getCertFirma();

        /* Verificamos a firma */

        String algoritmo = "SHA1withRSA";

        System.out.println(certFirma);

        if(!(comprobarCertificado(certFirma))) {
            System.out.println("CERTIFICADO DE REXISTRO INCORRECTO");
            return false;
        }

        // Obtener la clave publica do trustStore

        KeyStore ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(pathCliente + nosoTrustStore), nosoContrasinalTS.toCharArray());

        /*******************************************************************
         *                   Verificacion
         ******************************************************************/

        System.out.println("***      Verificando:         *** ");

        // Obter a clave publica do trustStore
        PublicKey clavePublicaCliente = ks.getCertificate("server_cer").getPublicKey();

        System.out.println("*** CLAVE PUBLICA DO SERVIDOR ***");
        System.out.println(clavePublicaCliente);

        // Creamos un objeto para verificar
        Signature verifier = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para verificar

        verifier.initVerify(clavePublicaCliente);
        byte[] datosServer = getDatosServer(resposta, peticion, arquivo);
        verifier.update(datosServer);

        boolean resultado = false;
        // Verificamos & resultado

        resultado = verifier.verify(resposta.getFirma());

        if (resultado == true)
            System.out.println("Documento correctamente rexistrado co número " + resposta.getIdRexistro());
        else {
            System.out.println("FIRMA INCORRECTA DO REXISTRADOR");
        }

        return resultado;
    }

    private static byte[] getDatosServer(Resposta resposta, Peticion peticion, byte[] arquivo) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write((byte) resposta.getIdRexistro());
        outputStream.write(resposta.getSeloTemporal());
        outputStream.write(arquivo);
        outputStream.write(peticion.getFirma());
        return outputStream.toByteArray();
    }

    private static byte[] getDatosComprobarFirma(Resposta resposta, byte[] doc ,byte[] firmaDoc) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write((byte) resposta.getIdRexistro());
        outputStream.write(resposta.getSeloTemporal());
        outputStream.write(doc);
        outputStream.write(firmaDoc);
        return outputStream.toByteArray();
    }

    private static boolean comprobarCertificado(String cert) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        String full_name = null;
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(pathCliente + nosoTrustStore), nosoContrasinalTS.toCharArray());

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
            if(full_name.equalsIgnoreCase(cert)) return true;

        }
        return false;
    }

    private static String obterNomeCertificado() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        String full_name = null;
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(pathCliente + nosoKeyStore), nosoContrasinalKS.toCharArray());

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

        }
        return full_name;
    }


    /*

     * Cifra ben, pero o descifrador do server non funciona ben, polo tanto será o ultimo que faga
     *
     * */
    private static void cifrador(String path) throws Exception {
        String provider = "SunJCE";
        FileInputStream 	ftextoclaro 	= new FileInputStream(path);
        FileOutputStream 	ftextocifrado 	= new FileOutputStream(pathCliente + "docsCliente/" +  "temporalCifrado");

        String algoritmo 		= "RSA";
        String transformacion1 	= "/ECB/PKCS1Padding"; //Relleno de longitud fija de 88 bits (11 bytes)
        String transformacion2 	= "/ECB/OAEPPadding"; // Este relleno tiene una longitud mayor y es variable
        int longclave 			= 2048;               // NOTA -- Probar a subir este valor e ir viendo como
        //         disminuye significativamente la velocidad de descifrado
        int longbloque;
        long t, tbi, tbf; 	    // tiempos totales y por bucle
        double lf; 				// longitud del fichero

        byte bloqueclaro[] 		= new byte[(longclave/8) - 11]; // *** NOTA: Calculo solo valido para relleno PKCS1Padding ****
        byte bloquecifrado[] 	= new byte[2048];

        /************************************************************
         * Xerar e almacear a clave
         ************************************************************/

        // Obtener la clave publica do trustStore

        KeyStore ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(pathCliente + nosoTrustStore), nosoContrasinalTS.toCharArray());

        // Obter a clave publica do trustStore

        // Obter a clave publica do trustStore
        PublicKey clavePublicaServer = ks.getCertificate("server_cer").getPublicKey();

        System.out.println("*** CLAVE PUBLICA DO SERVIDOR ***");
        System.out.println(clavePublicaServer);


        /************************************************************
         CIFRAR
         ************************************************************/
        System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave
                + " ************");

        Cipher cifrador = Cipher.getInstance(algoritmo +
                transformacion1);

        // Se cifra con la modalidad opaca de la clave

        cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaServer);


        // Datos para medidas de velocidad cifrado
        t = 0; lf = 0; tbi = 0;  tbf = 0;

        while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {

            lf = lf + longbloque;

            tbi = System.nanoTime();

            bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
            bloquecifrado = cifrador.doFinal();

            tbf = System.nanoTime();
            t = t + tbf - tbi;

            ftextocifrado.write(bloquecifrado);
        }

        // Escribir resultados velocidad cifrado

        System.out.println("*** FIN CIFRADO " + algoritmo + "-" + longclave
                + " Provider: " + provider);
        System.out.println("Bytes  cifrados = " + (int) lf);
        System.out.println("Tiempo cifrado  = " + t / 1000000 + " mseg");
        System.out.println("Velocidad       = " + (lf * 8 * 1000) / t + " Mpbs");

        // Cerrar ficheros
        ftextocifrado.close();
        ftextoclaro.close();
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
