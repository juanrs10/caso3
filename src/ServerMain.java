import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ServerMain {
    private static final int SERVER_PORT = 12345;
    private static final int RSA_KEY_SIZE = 1024;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey sessionKey;
    private HashMap<String, String> packageStatusTable;
    private DiffieHellmanParams diffieHellmanParams = new DiffieHellmanParams();
    private Integer x = 5;


    // public static void main(String[] args) {
    //     ServerMain server = new ServerMain();
    //     server.initializeMenu();
    // }

    // Método para inicializar el menú del servidor
    public void initializeMenu() {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;
        
        while (running) {
            System.out.println("Menú del Servidor:");
            System.out.println("1. Generar par de llaves RSA");
            System.out.println("2. Iniciar servidor");
            System.out.println("3. Salir");

            int choice = scanner.nextInt();
            switch (choice) {
                case 1:
                    generateKeyPair();
                    break;
                case 2:
                    // Start the server in a new thread for concurrent interaction
                    Thread serverThread = new Thread(() -> startServer());
                    serverThread.start();
                    running = false; // Exit the menu after starting the server
                    break;
                case 3:
                    System.out.println("Saliendo del menú.");
                    running = false;
                    break;
                default:
                    System.out.println("Opción no válida.");
            }
        }
        //scanner.close();
    }
    // Generar el par de llaves RSA (pública y privada)
    private void generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(RSA_KEY_SIZE);
            KeyPair keyPair = keyGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            System.out.println("public key: " + publicKey);
            privateKey = keyPair.getPrivate();

            // Guardar las llaves en archivos
            try (FileOutputStream fos = new FileOutputStream("publicKey.key")) {
                fos.write(publicKey.getEncoded());
            }
            try (FileOutputStream fos = new FileOutputStream("privateKey.key")) {
                fos.write(privateKey.getEncoded());
            }

            System.out.println("Llaves RSA generadas y guardadas.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Iniciar el servidor y aceptar conexiones
    public void startServer() {
        //generateKeyPair();
        //System.out.println("Iniciando el servidor...");
        populatePackageStatusTable(); // Inicializar la tabla de paquetes

        try (ServerSocket serverSocket = new ServerSocket(SERVER_PORT)) {
            //System.out.println("Servidor escuchando en el puerto " + SERVER_PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                //System.out.println("Cliente conectado: " + clientSocket.getInetAddress());

                // Crear y ejecutar un delegado para manejar la conexión del cliente
                ClientHandler clientHandler = new ClientHandler(clientSocket, packageStatusTable, privateKey,x);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Inicializar la tabla de estado de paquetes con datos de ejemplo
    private void populatePackageStatusTable() {
        packageStatusTable = new HashMap<>();
        packageStatusTable.put("cliente1;paquete123", "ENOFICINA");
        packageStatusTable.put("cliente2;paquete456", "RECOGIDO");
        // Añadir más entradas según sea necesario
    }
}
