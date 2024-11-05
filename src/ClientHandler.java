import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.sql.Time;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private HashMap<String, String> packageStatusTable;
    private PrivateKey privateKey;
    private SecretKey aesKey; // Llave de sesión AES compartida
    private IvParameterSpec iv; // Vector de inicialización para AES
    private DiffieHellmanParams diffieHellmanParams = new DiffieHellmanParams();
    private final Integer x; 
    private BigInteger kShared; 

    public ClientHandler(Socket socket, HashMap<String, String> packageStatusTable, PrivateKey privateKey, Integer x) {
        this.clientSocket = socket;
        this.packageStatusTable = packageStatusTable;
        this.privateKey = privateKey;
        this.x = x; 

        // Inicializar clave AES y IV
        initializeAESKey();
        generateIv();
    }

    @Override
    public void run() {
        try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
         ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {

            // Step 1: Time the response to the challenge
            long challengeStart = System.currentTimeMillis();
            // Step 1: Receive and decrypt the challenge
            byte[] encryptedChallenge = (byte[]) in.readObject();
            String decryptedChallenge = decryptDataRSA(encryptedChallenge);
            //System.out.println("Challenge decrypted: " + decryptedChallenge);

            // Step 2: Send decrypted challenge as response
            out.writeObject(decryptedChallenge);
            long challengeEnd = System.currentTimeMillis();
            System.out.println("Challenge completion: "+ (challengeEnd-challengeStart) + " ms");


            // Step 3: Receive OK/ERROR from client for challenge verification
            String challengeStatus = (String) in.readObject();
            if (!"OK".equals(challengeStatus)) {
                System.out.println("Client failed to verify challenge.");
                return;
            }

            // Step 4: Send Diffie-Hellman parameters with Digital Signature
            //Time the Diffie-Hellman parameter generation
            long dhGenStart = System.currentTimeMillis();
            BigInteger g = DiffieHellmanParams.P;
            BigInteger p = DiffieHellmanParams.G;
            BigInteger g_xBigInt = g.modPow(BigInteger.valueOf(x), p);

            // Create digital signature for (challenge, g, p, g_xBigInt)
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey); // The server's private key
            String challenge = "DiffieHelmanChallenge";

            // Update signature with the values to be signed
            signature.update(challenge.getBytes(StandardCharsets.UTF_8));
            signature.update(g.toByteArray());
            signature.update(p.toByteArray());
            signature.update(g_xBigInt.toByteArray());

            byte[] signedData = signature.sign(); // Signature for (challenge, g, p, g_xBigInt)

            // Send parameters and signature to the client
            out.writeObject(new Object[]{g, p, g_xBigInt, signedData});

            long dhGenEnd = System.currentTimeMillis();
            System.out.println("Time to generate DH parameters: " + (dhGenEnd - dhGenStart) + " ms");


            
            // Step 5: Receive OK/ERROR from client for DH parameters verification
            long verificationStart = System.currentTimeMillis();
            String dhStatus = (String) in.readObject();
            //System.out.println("status: "+ dhStatus);
            if (!"OK".equals(dhStatus)) {
                //System.out.println("Client failed to verify Diffie-Hellman parameters.");
                return;
            }

            // Step 6: Receive G_y from client and calculate (G_y)^x to generate K_shared

            // Receive G_y from client
            BigInteger g_y = (BigInteger) in.readObject();
            BigInteger K_shared = g_y.modPow(BigInteger.valueOf(x), p); // Server calculates K_shared (G_y)^x


            // Derive K_AB1 and K_AB2 from K_shared
            byte[] kSharedBytes = K_shared.toByteArray();
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(kSharedBytes);
            byte[] kAb1Bytes = Arrays.copyOfRange(hash, 0, 32); // First 256 bits for K_AB1
            byte[] kAb2Bytes = Arrays.copyOfRange(hash, 32, 64); // Last 256 bits for K_AB2

            SecretKey K_AB1 = new SecretKeySpec(kAb1Bytes, "AES");
            SecretKey K_AB2 = new SecretKeySpec(kAb2Bytes, "AES");

            // Generate and send IV to client for encryption
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes); // Generate random IV
            out.writeObject(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            //System.out.println("IV sent and encryption initialized.");
            
            //El servidor verifica C(K_AB1, userId), HMAC(K_AB2, userId), C(K_AB1, packageId), HMAC(K_AB2, packageId) enviados por el cliente

            // Step 8: Verify encrypted userId and packageId along with their HMACs

            // Receive encrypted userId and its HMAC from client
            byte[] encryptedUserId = (byte[]) in.readObject();
            byte[] hmacUserId = (byte[]) in.readObject();

            // Receive encrypted packageId and its HMAC from client
            byte[] encryptedPackageId = (byte[]) in.readObject();
            byte[] hmacPackageId = (byte[]) in.readObject();

            // Decrypt userId with K_AB1
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
            byte[] decryptedUserIdBytes = aesCipher.doFinal(encryptedUserId);
            String decryptedUserId = new String(decryptedUserIdBytes, StandardCharsets.UTF_8);
            //System.out.println("Decrypted userId: " + decryptedUserId);

            // Decrypt packageId with K_AB1
            byte[] decryptedPackageIdBytes = aesCipher.doFinal(encryptedPackageId);
            String decryptedPackageId = new String(decryptedPackageIdBytes, StandardCharsets.UTF_8);
            //System.out.println("Decrypted packageId: " + decryptedPackageId);

            // Verify HMAC for userId
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(K_AB2);
            byte[] calculatedHmacUserId = hmac.doFinal(decryptedUserIdBytes);
            boolean isUserIdValid = MessageDigest.isEqual(calculatedHmacUserId, hmacUserId);

            // Verify HMAC for packageId
            byte[] calculatedHmacPackageId = hmac.doFinal(decryptedPackageIdBytes);
            boolean isPackageIdValid = MessageDigest.isEqual(calculatedHmacPackageId, hmacPackageId);

            // Send verification result to client
            String estado = "OK";
            if (isUserIdValid && isPackageIdValid) {
                //System.out.println("Verification successful: userId and packageId are valid.");
            } else {
                estado = "ERROR";
                //System.out.println("Verification failed: Invalid HMAC for userId or packageId.");
            }

            //C(K_AB1, estado)
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
            byte[] encryptedEstado = aesCipher.doFinal(estado.getBytes(StandardCharsets.UTF_8));
            out.writeObject(encryptedEstado);

            //HMAC(K_AB2,estado)
            hmac.init(K_AB2);
            byte[] hmacEstado = hmac.doFinal(estado.getBytes(StandardCharsets.UTF_8));
            out.writeObject(hmacEstado);
            long verificationEnd = System.currentTimeMillis();
            System.out.println("Time to verify request: " + (verificationEnd - verificationStart) + " ms");
    

        } catch (Exception e) {
        e.printStackTrace();
        }
    }

    // Calculate HMAC using the server's private key
    private byte[] calculateServerHmac(BigInteger g, BigInteger p, BigInteger g_x) {
        try {
            // Convert the data to a single byte array in one step
            byte[] data = (g.toString() + p.toString() + g_x.toString()).getBytes(StandardCharsets.UTF_8);

            // Initialize the HMAC with the server's private key bytes
            Mac hmac = Mac.getInstance("HmacSHA384");
            SecretKeySpec keySpec = new SecretKeySpec(privateKey.getEncoded(), "HmacSHA384");
            hmac.init(keySpec);

            // Generate and return the HMAC
            return hmac.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Error: Server HMAC null");
        return null;
    }

    // Método para descifrar la solicitud con RSA
    private String decryptDataRSA(byte[] encryptedData) {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = rsaCipher.doFinal(encryptedData);
            return new String(decryptedData); // Convertir los datos a String
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Método para cifrar la respuesta con AES en modo CBC
    private byte[] encryptDataAES(String response) {
        try {
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            return aesCipher.doFinal(response.getBytes()); // Cifrar la respuesta y devolver los bytes
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Generar una llave AES de 256 bits
    private void initializeAESKey() {
        try {
            // Crear una llave secreta para AES (esto debería ser compartido de manera segura)
            byte[] keyBytes = new byte[32]; // 256 bits (32 bytes)
            aesKey = new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Generar el vector de inicialización (IV) para AES en modo CBC
    private void generateIv() {
        byte[] ivBytes = new byte[16]; // 16 bytes para AES en CBC
        iv = new IvParameterSpec(ivBytes);
    }

    // Obtener el estado del paquete de la tabla
    private String getPackageStatus(String request) {
        return packageStatusTable.getOrDefault(request, "DESCONOCIDO");
    }

    // Método para calcular el HMAC de la respuesta
    private byte[] calculateHMAC(String message) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(aesKey); // Usa la misma llave AES para HMAC
            return hmac.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
