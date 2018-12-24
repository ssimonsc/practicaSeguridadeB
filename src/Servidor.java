import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class Servidor extends Thread {
    /* Erros */
    private static int CERTFIRMA = -1;
    private static int FIRMA = -2;

    /* Constantes */
    private static SSLServerSocket meuServerSocket;
    private static Socket cliente;
    private static String path = "/home/ssimonsc/universidade/seguridade/servidor/";
    private static String nosoKeyStore = "almacenes/servidor/server.jce";
    private static String nosoTrustStore = "almacenes/truestore_compartido/truestore.jce";
    private static String nosoContrasinalKS = "passserver";
    private static String nosoContrasinalTS = "passcacerts";
    private static int idRexistro = 0;
    private static HashMap<Integer, Documentos> listaDocsPublicos = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsPrivados = new HashMap<Integer, Documentos>();
    private static HashMap<Integer, Documentos> listaDocsXeral = new HashMap<Integer, Documentos>();
    static byte[] parametros;

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

        System.setProperty("javax.net.ssl.keyStore",         path + nosoKeyStore);
        System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", nosoContrasinalKS);

        // Almacen de confianza

        System.setProperty("javax.net.ssl.trustStore",          path + nosoTrustStore);
        System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", nosoContrasinalTS);
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
                            if(!comprobarPeticion(peticion)) {
                                break;
                            }
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
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (UnrecoverableEntryException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (Exception e) {
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
                char[] contrasinal = nosoContrasinalKS.toCharArray();

                ctx = SSLContext.getInstance("TLS");
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

                ks  = KeyStore.getInstance("JCEKS");
                ks.load(new FileInputStream(path + nosoKeyStore), contrasinal);

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

    public static boolean verificarPeticion(Peticion peticion) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, UnrecoverableEntryException, NoSuchProviderException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        byte[] arquivo;
        byte[] firma = peticion.getFirma();
        String certFirma = peticion.getCertFirma();

        /* Verificamos a firma */

        String algoritmo = "SHA1withRSA";

        System.out.println(certFirma);

        if(!(comprobarCertificado(certFirma))) {
            System.out.println("CERTIFICADO DE FIRMA INCORRECTO. Desbotando peticion...");
            Resposta resposta = new Resposta(CERTFIRMA);
            enviarResposta(resposta);
            return false;
        }

        // Obtener la clave publica do trustStore

        KeyStore ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(path + nosoTrustStore), nosoContrasinalTS.toCharArray());

        /*******************************************************************
         *                   Verificacion
         ******************************************************************/

        System.out.println("***      Verificando:         *** ");

        // Obter a clave publica do trustStore
        PublicKey clavePublicaCliente = ks.getCertificate("client1_cert").getPublicKey();

        System.out.println("*** CLAVE PUBLICA DO CLIENTE ***");
        System.out.println(clavePublicaCliente);

        // Creamos un objeto para verificar
        Signature verifier = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para verificar

        verifier.initVerify(clavePublicaCliente);

        if(peticion.getTipoConfifencial()) {
            gardarArquivo("temporalCifrado", peticion.getArquivo());
            descifradorAsimetrico();
            arquivo = procesarArquivoByte(path + "docs/temporalSenCifrar");
            eliminarArquivo(path + "docs/temporalCifrado");
            eliminarArquivo(path + "docs/temporalSenCifrar");
        } else arquivo = peticion.getArquivo();

        verifier.update(arquivo);

        boolean resultado = false;
        // Verificamos & resultado

        resultado = verifier.verify(firma);

        if (resultado == true) System.out.println("Firma CORRECTA");
        else {
            System.out.println("Firma NON correcta");
            Resposta resposta = new Resposta(FIRMA);
            enviarResposta(resposta);
        }

        return resultado;
    }

    private static boolean comprobarPeticion(Peticion peticion) {
        if(!listaDocsXeral.containsKey(peticion.getIdRexistro())) {
            System.out.println("DOCUMENTO NON EXISTENTE");
            return false;
        } else if(listaDocsPrivados.containsKey(peticion.getIdRexistro())) {
            if(!listaDocsXeral.get(peticion.getIdRexistro()).getIdPropietario().equalsIgnoreCase(peticion.getCertFirma())) {
                System.out.println("ACCESO NON PERMITIDO");
                return false;
            }
        }
        return true;
    }

    private static boolean comprobarCertificado(String cert) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        String full_name = null;
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(new FileInputStream(path + nosoTrustStore), nosoContrasinalTS.toCharArray());

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


//    public static byte[] descifrador(byte[] arquivoCifrado) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        String provider = "SunJCE";
//        String algoritmo = "RSA";
//        String transformacion = "/ECB/PKCS1Padding";
//
//        System.out.println("\n\nDocumento cifrado: ");
//        System.out.println(arquivoCifrado);
//
//        char[] key_password = nosoContrasinal.toCharArray();
//        KeyStore ks;
//        ks = KeyStore.getInstance("JCEKS");
//
//        // Cargamos el keystore
//        ks.load(new FileInputStream(path + nosoKeyStore), key_password);
//
//        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
//                ks.getEntry("serverkey",
//                        new KeyStore.PasswordProtection(key_password));
//
//
//        PrivateKey privateKey = (PrivateKey) ks.getKey("serverkey", key_password);
//        System.out.println("Clave privada: \n\n" + privateKey);
//        // DESCIFRAR
//        // *****************************************************************************
//
//        Cipher descifrador = Cipher.getInstance(algoritmo + transformacion);
//
//        descifrador.init(Cipher.DECRYPT_MODE, privateKey);
//
//      //  byte[] arquivoDescifrado = descifrador.update(arquivoCifrado);
//        byte[] arquivoDescifrado = descifrador.doFinal(arquivoCifrado);
//
//        System.out.println("\n\nDocumento non cifrado: ");
//        System.out.println(arquivoDescifrado);
//
//        System.out.println("Arquivo descifrado con éxito");
//        return arquivoDescifrado;
//    }

    public static byte[] cifrador(byte[] arquivoSenCifrar) throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchPaddingException {
        String provider = "SunJCE";
        String algoritmo = "AES";
        String transformacion = "/CBC/PKCS5Padding";
      //  FileOutputStream fclave        = new FileOutputStream(path + nosoKeyStore);
      //  FileInputStream fclave_in       = new FileInputStream(path + nosoKeyStore);
        try {
            String secretEntryAlias, secretEntryPass;

                secretEntryAlias = "server_aes";

            secretEntryPass = "passserver";
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(path + nosoKeyStore), nosoContrasinalKS.toCharArray());
            KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) ks.getEntry(secretEntryAlias,
                    new KeyStore.PasswordProtection(secretEntryPass.toCharArray()));
            byte[] kreg_raw = skEntry.getSecretKey().getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(kreg_raw, algoritmo);
            Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);

            if (algoritmo.equals("AES")) {


                cifrador.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]));
                return cifrador.doFinal(arquivoSenCifrar);
            } else {
                cifrador.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            }
            return cifrador.update(arquivoSenCifrar);

            // cifrador.init( Cipher.ENCRYPT_MODE, secretKeySpec );
            // return cifrador.update(documento.documento);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Non se pudo cifrar o archivo");
        return null;

    }


    public static void rexistrar(Peticion peticion) throws Exception {
        idRexistro++;
        GregorianCalendar data = new GregorianCalendar();
        Date seloTemporal = data.getTime();
        byte[] seloTemporalByte =  xerarSeloTemporal(seloTemporal);
        byte[] firma = firmador(idRexistro, seloTemporalByte, peticion);

        Documentos novoDocumento = new Documentos(idRexistro, peticion.getCertFirma(), peticion.getNomeArquivo(), seloTemporal, peticion.getTipoConfifencial());
        byte[] arquivoCifrado = null;
        if (peticion.getTipoConfifencial()) {
            gardarArquivo("temporalCifrado",peticion.getArquivo());
            descifradorAsimetrico();
            arquivoCifrado = cifrador(procesarArquivoByte(path + "docs/temporalSenCifrar"));
            eliminarArquivo(path + "docs/temporalCifrado");
            eliminarArquivo(path + "docs/temporalSenCifrar");
            listaDocsPrivados.put(novoDocumento.getIdRexistro(), novoDocumento);
        }
        else
            listaDocsPublicos.put(novoDocumento.getIdRexistro(), novoDocumento);

        listaDocsXeral.put(novoDocumento.getIdRexistro(), novoDocumento);

        if (peticion.getTipoConfifencial()) {
            DocumentoAlmacenado doc = new DocumentoAlmacenado(peticion.getNomeArquivo(), arquivoCifrado, firma, idRexistro, seloTemporalByte);
            gardarDocumento(doc, false);
        }
        else {
            DocumentoAlmacenado doc = new DocumentoAlmacenado(peticion.getNomeArquivo(), peticion.getArquivo(), firma, idRexistro, seloTemporalByte);
            gardarDocumento(doc, true);
        }

        Resposta resposta = new Resposta(0, idRexistro, seloTemporalByte, firma, "CN=Server,C=ES");
        enviarResposta(resposta);
    }

    private static void eliminarArquivo(String pathArquivo) {
        File arquivo = new File(pathArquivo);
        arquivo.delete();
    }

    private static void gardarArquivo(String nome, byte[] arquivoByte) throws IOException {
        File arquivo = new File(path + "docs/" + nome);
        FileOutputStream fos = new FileOutputStream(arquivo);
        fos.write(arquivoByte);
        fos.close();
    }

    public static byte[] procesarArquivoByte(String path) throws IOException {
        File arquivo = new File(path);
        byte[] arquivoByte = new byte[(int) arquivo.length()];
        FileInputStream FiS = new FileInputStream(arquivo);
        FiS.read(arquivoByte);
        FiS.close();

        return  arquivoByte;
    }

    private static void descifradorAsimetrico() throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String provider = "SunJCE";
        int longclave 			= 2048;               // NOTA -- Probar a subir este valor e ir viendo como
        FileInputStream  ftextocifrado2 = new FileInputStream( path + "docs/" + "temporalCifrado");
        FileOutputStream ftextoclaro2 = new FileOutputStream( path + "docs/" + "temporalSenCifrar");

        byte bloquecifrado2[] = new byte[(longclave/8)];
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
        String		entry_alias		= "server";


        // Obter a clave privada do keystore

        ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(path + nosoKeyStore),  ks_password);

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

    private static void cifradorAsimetrico() throws Exception {
        String provider = "SunJCE";
        FileInputStream 	ftextoclaro 	= new FileInputStream(path + "docs/" +  "temporalSenCifrar");
        FileOutputStream 	ftextocifrado 	= new FileOutputStream(path + "docs/" +  "temporalCifrado");

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

        ks.load(new FileInputStream(path + nosoTrustStore), nosoContrasinalTS.toCharArray());

        // Obter a clave publica do trustStore

        // Obter a clave publica do trustStore
        PublicKey clavePublicaServer = ks.getCertificate("client1_cert").getPublicKey();

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

    private static void gardarDocumento(DocumentoAlmacenado doc, boolean publico) throws Exception {
        File ficheiro = null;
        if(publico) ficheiro = new File(path + "docs/" + doc.getNome() + doc.getIdRexistro() + ".sig");
        else ficheiro = new File(path + "docs/" + doc.getNome() + doc.getIdRexistro() + ".sig.cif");
        System.out.println("Guardando en :" + ficheiro.getAbsolutePath());
        OutputStream os = new FileOutputStream(ficheiro);
        ObjectOutputStream oos = new ObjectOutputStream(os);
        oos.writeObject(doc);
        oos.close();
    }


    public void listar(Peticion peticion) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        boolean tipo = peticion.getTipoConfifencial();
        String certFirma = peticion.getCertFirma();
        if(!comprobarCertificado(certFirma)) {
            System.out.println("CERTIFICADO INCORRECTO");
            Resposta resposta = new Resposta(CERTFIRMA);
            enviarResposta(resposta);
        } else {
            HashMap<Integer, Documentos> listaDocs;
            if (tipo) listaDocs = obterPrivados(certFirma);
            else listaDocs = listaDocsPublicos;
            Resposta minhaResposta = new Resposta(listaDocs);
            enviarResposta(minhaResposta);
        }
    }

    public static void recuperar(Peticion peticion) throws Exception {
        byte[] arquivo;
        DocumentoAlmacenado doc;
        byte[] firma = new byte[2000];

        int idRex = peticion.getIdRexistro();
        String nome = listaDocsXeral.get(idRex).getNomeArquivo();
        boolean tipoConfidencial = listaDocsXeral.get(idRex).getTipoConfidencialidade();
        if(tipoConfidencial) {
            doc = procesarArquivo(path + "docs/" + nome + idRex + ".sig.cif");
            byte[] arquivoDescifrado = descifrador(doc.getArquivo());
            gardarArquivo("temporalSenCifrar", arquivoDescifrado);
            cifradorAsimetrico();
            arquivo = procesarArquivoByte(path + "docs/temporalCifrado");
            eliminarArquivo(path + "docs/temporalSenCifrar");
            eliminarArquivo(path + "docs/temporalCifrado");
        } else {
            doc = procesarArquivo(path + "docs/" + nome + idRex + ".sig");
            arquivo = doc.getArquivo();
        }

        Resposta minhaResposta = new Resposta(0, tipoConfidencial, idRex, doc.getSeloTemporal(), arquivo, doc.getFirma(), "CN=Server,C=ES");
        minhaResposta.setNomeArquivo(doc.getNome());
        enviarResposta(minhaResposta);
    }

    public static DocumentoAlmacenado procesarArquivo(String pathArquivo) throws IOException, ClassNotFoundException {
        File arquivo = new File(pathArquivo);
        ObjectInputStream oos = new ObjectInputStream(new FileInputStream(arquivo));
        DocumentoAlmacenado doc = (DocumentoAlmacenado) oos.readObject();
        oos.close();
        return  doc;
    }

    public static void  enviarResposta(Resposta minhaResposta) throws IOException {
        OutputStream out = cliente.getOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(minhaResposta);
    }

    public static byte[] xerarSeloTemporal(Date data) {
        byte[] selloTemporal;
        selloTemporal = data.toString().getBytes();
        return selloTemporal;
    }

    public  static  byte[] descifrador(byte[] arquivoCifrado) {
        String provider = "SunJCE";
        String algoritmo = "AES";
        String transformacion = "/CBC/PKCS5Padding";
        String secretEntryAlias = "server_aes";

        KeyStore ks;
        try {
            ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(path + nosoKeyStore), nosoContrasinalKS.toCharArray());
            KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) ks.getEntry(secretEntryAlias,
                    new KeyStore.PasswordProtection(nosoContrasinalKS.toCharArray()));
            byte[] kreg_raw = skEntry.getSecretKey().getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(kreg_raw, algoritmo);

            Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);
            if (algoritmo.equalsIgnoreCase("AES")) {
                descifrador.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]));
                return descifrador.doFinal(arquivoCifrado);
            } else {
                descifrador.init(Cipher.DECRYPT_MODE, secretKeySpec);
            }
            return descifrador.update(arquivoCifrado);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableEntryException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] firmador(int idRexistro, byte[] seloTemporal, Peticion peticion) throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException {
        byte[] arquivo;

        String 		algoritmo        = "SHA1withRSA";
        int    		longbloque;
        byte   		bloque[]         = new byte[1024];
        long   		filesize         = 0;

        // Variables para el KeyStore

        KeyStore    ks;
        char[]      ks_password  	= nosoContrasinalKS.toCharArray();
        char[]      key_password 	= nosoContrasinalKS.toCharArray();
        String		entry_alias		= "server";

        System.out.println("******************************************* ");
        System.out.println("*               FIRMA                     * ");
        System.out.println("******************************************* ");

        // Obter a clave privada do keystore

        ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(path + nosoKeyStore),  ks_password);

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

        if(peticion.getTipoConfifencial()) {
            gardarArquivo("temporalCifrado", peticion.getArquivo());
            descifradorAsimetrico();
            arquivo = procesarArquivoByte(path + "docs/temporalSenCifrar");
            eliminarArquivo(path + "docs/temporalSenCifrar");
            eliminarArquivo(path + "docs/temporalCifrado");
        } else {
            arquivo = peticion.getArquivo();
        }

        byte[] datosFirma = getDatosFirma(idRexistro, seloTemporal, arquivo, peticion.getFirma());
        signer.update(datosFirma);
        firma = signer.sign();


        return firma;
    }

    private static byte[] getDatosFirma(int idRexistro, byte[] seloTemporal, byte[] arquivo, byte[] firma) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        System.out.println(idRexistro + "\n" + seloTemporal + "\n" + arquivo + "\n" + firma);
        outputStream.write((byte) idRexistro);
        outputStream.write(seloTemporal);
        outputStream.write(arquivo);
        outputStream.write(firma);
        return outputStream.toByteArray();
    }

    private HashMap<Integer, Documentos> obterPrivados(String idPropietario) {
        HashMap<Integer, Documentos> meusDocumentos = new HashMap<>();
        int i = 0;
        for (Map.Entry<Integer, Documentos> entry : listaDocsPrivados.entrySet()) {
            i++;
            if(entry.getValue().getIdPropietario().equalsIgnoreCase(idPropietario)) meusDocumentos.put(i, entry.getValue());
        }
        return meusDocumentos;
    }

}
