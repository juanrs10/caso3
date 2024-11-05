import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.lang.model.type.DeclaredType;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ClientMain {
    private static final String SERVER_HOST = "localhost"; // Dirección del servidor
    private static final int SERVER_PORT = 12345;          // Puerto del servidor
    private SecretKey sessionKey;                          // Llave de sesión AES
    private PublicKey serverPublicKey;                     // Llave pública del servidor
    private IvParameterSpec iv;                            // Vector de inicialización
    private DiffieHellmanParams diffieHellmanParams = new DiffieHellmanParams();
    private Integer y = 10; 

    public ClientMain() {
        // Inicializar el cliente, cargar la llave pública y generar el vector de inicialización
        loadServerPublicKey();
        generateIv();
    }

    public static void main(String[] args) {
        ClientMain client = new ClientMain();
        client.sendRequest("cliente1", "paquete123");
    }

    // Cargar la llave pública del servidor desde archivo
    private void loadServerPublicKey() {
        try {
            // Leer el contenido del archivo de la llave pública
            byte[] keyBytes = Files.readAllBytes(Paths.get("./publicKey.key"));

            // Decodificar la llave pública en formato X.509
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            serverPublicKey = keyFactory.generatePublic(keySpec);

            System.out.println("Llave pública del servidor cargada exitosamente.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para enviar una solicitud de estado de paquete
    public void sendRequest(String userId, String packageId) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
         ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
         ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Step 1: Generate challenge and send encrypted challenge to server
            String challenge = "Reto";
            byte[] encryptedChallenge = encryptDataRSA(challenge); //CHECK CUZ THERE NO SESH KEY
            out.writeObject(encryptedChallenge);

            // Step 2: Receive server Rta response and verify
            String response = (String) in.readObject();

            if (challenge.equals(response)) {
                out.writeObject("OK");
                //System.out.println("Server challenge verified.");
            } else {
                out.writeObject("ERROR");
                System.out.println("Server challenge verification failed.");
                return;
            }

            // Step 3: Receive Diffie-Hellman parameters from server and verify signature
            Object[] dhParamsAndSignature = (Object[]) in.readObject();
            BigInteger g = (BigInteger) dhParamsAndSignature[0];
            BigInteger p = (BigInteger) dhParamsAndSignature[1];
            BigInteger g_xBigInt = (BigInteger) dhParamsAndSignature[2];
            byte[] signedData = (byte[]) dhParamsAndSignature[3];

            // Verify signature using the server's public key
            PublicKey publicKey = serverPublicKey; // Load the server's public key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            // Update signature with the received parameters
            signature.update(challenge.getBytes(StandardCharsets.UTF_8));
            signature.update(g.toByteArray());
            signature.update(p.toByteArray());
            signature.update(g_xBigInt.toByteArray());

            boolean signatureCheck = signature.verify(signedData); // Verify the signature

            if (!signatureCheck) {
                out.writeObject("OK");
                //System.out.println("Diffie-Hellman parameters verified.");
            } else {
                out.writeObject("ERROR");
                System.out.println("Diffie-Hellman parameters verification failed.");
            }
            //---HERE---

            // Step 6: Cliente calcula (G_x)_y, Genera llave simétrica para cifrar K_AB1 y llave simétrica para MAC K_AB2, envía (G_x)_y al servidor
            BigInteger K_shared = g_xBigInt.modPow(BigInteger.valueOf(y), p); // Client calculates K_shared
            
            // Derive K_AB1 and K_AB2 from K_shared
            byte[] kSharedBytes = K_shared.toByteArray();
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(kSharedBytes);

            // Split hash into two keys
            byte[] kAb1Bytes = Arrays.copyOfRange(hash, 0, 32); // First 256 bits for K_AB1
            byte[] kAb2Bytes = Arrays.copyOfRange(hash, 32, 64); // Last 256 bits for K_AB2

            // Create SecretKey objects for AES encryption and MAC
            SecretKey K_AB1 = new SecretKeySpec(kAb1Bytes, "AES");
            SecretKey K_AB2 = new SecretKeySpec(kAb2Bytes, "AES");

            // Calculate G_y and K_shared
            BigInteger g_y = g.modPow(BigInteger.valueOf(y), p);
            out.writeObject(g_y);  // Send G_y to server

            // Receive IV from the server
            byte[] ivBytes = (byte[]) in.readObject();
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // Step 7: Client encrypts and sends C(K_AB1, userId), HMAC(K_AB2, userId), C(K_AB1, packageId), HMAC(K_AB2, packageId)

            // Encrypt userId with K_AB1
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
            byte[] encryptedUserId = aesCipher.doFinal(userId.getBytes(StandardCharsets.UTF_8));

            // Encrypt packageId with K_AB1
            byte[] encryptedPackageId = aesCipher.doFinal(packageId.getBytes(StandardCharsets.UTF_8));

            // Generate HMAC for userId with K_AB2
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(K_AB2);
            byte[] hmacUserId = hmac.doFinal(userId.getBytes(StandardCharsets.UTF_8));

            // Generate HMAC for packageId with K_AB2
            byte[] hmacPackageId = hmac.doFinal(packageId.getBytes(StandardCharsets.UTF_8));

            // Send encrypted and HMAC'd values to the server
            out.writeObject(encryptedUserId); // C(K_AB1, userId)
            out.writeObject(hmacUserId);      // HMAC(K_AB2, userId)
            out.writeObject(encryptedPackageId); // C(K_AB1, packageId)
            out.writeObject(hmacPackageId);      // HMAC(K_AB2, packageId)

            //System.out.println("Sent encrypted and HMAC'd userId and packageId to the server.");

            //Recibe C(K_AB1,estado) y HMAC(K_AB2,estado) y verifica
            byte[] encryptedEstado = (byte[]) in.readObject();
            byte[] hmacEstado = (byte[]) in.readObject();

            aesCipher.init(Cipher.DECRYPT_MODE, K_AB1, ivSpec);
            byte[] decryptedEstadoBytes = aesCipher.doFinal(encryptedEstado);

            // Calcular el HMAC del estado desencriptado usando K_AB2
            hmac.init(K_AB2);
            byte[] calculatedHmacEstado = hmac.doFinal(decryptedEstadoBytes);

            // Verificar la validez del cypheredEstado comparando los HMACs
            boolean isHmacValid = MessageDigest.isEqual(hmacEstado, calculatedHmacEstado);

            // Verificar si el estado es válido
            boolean isCypheredEstadoValid = (decryptedEstadoBytes != null && decryptedEstadoBytes.length > 0);

            if (isCypheredEstadoValid && isHmacValid) {
                out.writeObject("TERMINAR");
                System.out.println("cypheredEstado y HMAC verificados correctamente.");
                System.out.println("El protocolo finalizó correctamente con el estado: Terminar");
            } else {
                out.writeObject("ERROR");
                System.out.println("Verificación fallida para cypheredEstado o HMAC.");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to verify HMAC from server using the server's public key
    private boolean verifyServerHmac(BigInteger g, BigInteger p, byte[] signedHmac, BigInteger g_x) {
        try {
            // Convert g, p, and g_x to a single byte array in one step
            byte[] data = (g.toString() + p.toString() + g_x.toString()).getBytes(StandardCharsets.UTF_8);

            // Initialize the HMAC with the server's public key bytes
            Mac hmac = Mac.getInstance("HmacSHA384");
            SecretKeySpec keySpec = new SecretKeySpec(serverPublicKey.getEncoded(), "HmacSHA384");
            hmac.init(keySpec);

            // Compute the HMAC and compare with the received signedHmac
            byte[] computedHmac = hmac.doFinal(data);
            return MessageDigest.isEqual(computedHmac, signedHmac);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    // Generar el vector de inicialización (IV)
    private void generateIv() {
        byte[] ivBytes = new byte[16];
        // Generar 16 bytes aleatorios para el IV
        iv = new IvParameterSpec(ivBytes);
    }

    // Método para encriptar la solicitud con AES y firmarla
    private byte[] encryptRequest(String userId, String packageId) {
        try {
            String message = userId + ";" + packageId;
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
            return cipher.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Método para cifrar datos con la llave pública del servidor (RSA)
    private byte[] encryptDataRSA(String data) {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            return rsaCipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



    // Método para descifrar la respuesta con AES
    private byte[] decryptDataAES(byte[] encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Método para validar la respuesta usando HMAC
    private boolean validateResponse(byte[] response) {
        try {
            Mac mac = Mac.getInstance("HmacSHA384");
            mac.init(new SecretKeySpec(sessionKey.getEncoded(), "HmacSHA384"));
            byte[] computedHmac = mac.doFinal(response);
            // Verificar que el HMAC coincide con el recibido (pendiente implementación de comparación)
            return true; // Agregar lógica de comparación del HMAC
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private void initializeSessionKey() {
    try {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        sessionKey = keyGen.generateKey();
    } catch (Exception e) {
        e.printStackTrace();
    }

    }

    private boolean validateResponse(byte[] response, byte[] receivedHmac) {
    try {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(new SecretKeySpec(sessionKey.getEncoded(), "HmacSHA384"));
        byte[] computedHmac = mac.doFinal(response);
        return MessageDigest.isEqual(computedHmac, receivedHmac); // Compara ambos HMACs
    } catch (Exception e) {
        e.printStackTrace();
    }
    return false;
}

}
