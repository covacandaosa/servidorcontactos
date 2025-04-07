package fp.dam.psp.servidorcontactos.cliente;
// CLIENTE

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9000)) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Leer certificado enviado por el servidor
            String b64Certificate = in.readUTF();
            byte[] certificateBytes = Base64.getDecoder().decode(b64Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));

            // Modificar este bloque de código para generar la clave según se explica en
            // https://www.baeldung.com/java-aes-encryption-decryption usando el algoritmo
            // de derivación de clave PBKDF2WithHmacSHA256.
            // Se enviará el vector de inicialización (iv) usado por el algoritmo "AES/GCM/NoPadding" en lugar del algoritmo (linea 48).
            // {{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{

            // Crear clave secreta.
            /*Este genera una clave aleatoria pero no derivada, el cambio que
             1: Lo que queremos hacer es usar un metodo más seguro y controlado, con contraseña y alt,
             por lo que modificamos ese bloque de código*/

            //// KeyGenerator kg = KeyGenerator.getInstance("AES");
            //// kg.init(256);
            //// SecretKey key = kg.generateKey();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Crear clave secreta usando PBKDF2WithHmacSHA256
            char[] password = "clave-secreta".toCharArray(); // Puedes hacer esto configurable
            byte[] salt = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt); // Salt aleatoria

            int iterations = 65536;
            int keyLength = 256;

            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derivedKey = factory.generateSecret(spec).getEncoded();
            SecretKey key = new SecretKeySpec(derivedKey, "AES");

///////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Cifrar la clave secreta con la clave pública del servidor

            Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            byte[] encriptedKey = cipher.doFinal(key.getEncoded());

/////////////////////////////////////////////////////////////////////////////////////////////////////

            // 2: Enviar al servidor la clave secreta cifrada y codificada en Base64
            // modificar este código:
            //out.writeUTF(Base64.getEncoder().encodeToString(encriptedKey));
            // Enviar al servidor el algoritmo
            //out.writeUTF("AES");

            // Enviar al servidor la clave secreta cifrada y codificada en Base64
            out.writeUTF(Base64.getEncoder().encodeToString(encriptedKey));

            // Generar IV de 12 bytes para AES/GCM
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            out.writeUTF(Base64.getEncoder().encodeToString(iv));

            // Enviar al servidor el algoritmo
            out.writeUTF("AES/GCM/NoPadding");

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // }}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}

            // Realizar petición
            String peticion = "hola servidor";
            // Modificar el siguiente código para cifrar usando "AES/GCM/NoPadding" tal y como se explica en
            // https://www.baeldung.com/java-aes-encryption-decryption

            //3: sustituirlo, eso no es válido para GCM, porque no incluye ni el modo ni el IV
            //Cipher encrypCipher = Cipher.getInstance("AES");
            //encrypCipher.init(Cipher.ENCRYPT_MODE, key);
            //out.writeUTF(Base64.getEncoder().encodeToString(encrypCipher.doFinal(peticion.getBytes(StandardCharsets.UTF_8))));

            // Crear cifrador AES en modo GCM
            Cipher encrypCipher = Cipher.getInstance("AES/GCM/NoPadding");

            // GCM necesita el IV y una longitud de etiqueta de autenticación (128 bits = 16 bytes)
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            encrypCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Cifrar y enviar
            byte[] encryptedMessage = encrypCipher.doFinal(peticion.getBytes(StandardCharsets.UTF_8));
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage));

            //4: todavía estoy descifrando con "AES",
            // lo cual no es válido cuando el mensaje se ha cifrado con "AES/GCM/NoPadding" y un IV

            /*///Cipher decrypCipher = Cipher.getInstance("AES");
            ////decrypCipher.init(Cipher.DECRYPT_MODE, key);
            ////String respuesta = new String(decrypCipher.doFinal(Base64.getDecoder().decode(in.readUTF())));*/

            Cipher decrypCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decrypCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec); // Usa el mismo IV
            byte[] respuestaCifrada = Base64.getDecoder().decode(in.readUTF());
            String respuesta = new String(decrypCipher.doFinal(respuestaCifrada), StandardCharsets.UTF_8);

            System.out.println(respuesta);
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

}
