import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Scanner;

public class Cliente {
    private static Socket meuSocket;
    private static String pathCliente = "/home/ssimonsc/universidade/seguridade/cliente/";
    public static void main(String[] args) {
        int opcion = 5;
        try {
            Servidor meuServidor = new Servidor();
            meuServidor.start();
            meuSocket = establecerSocket("localhost", 3000);
            //  meuSocket.startHandshake(); // Protocolo SSL Handshake
            while (opcion !=0){
                opcion = imprimirMenu();
                elexirFuncion(opcion);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Socket establecerSocket(String host, int porto) throws  IOException {
        return  new Socket(host, porto);
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
