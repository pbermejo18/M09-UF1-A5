import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws UnsupportedEncodingException {
        Scanner scanner = new Scanner(System.in);

        // 1.1
        System.out.println("######################### 1.1 ##########################");
            System.out.println("Escriu un missatge: ");
            String missatge = scanner.nextLine();

            // genero la key
            KeyPair k = Xifrar.randomGenerate(1028);

            // xifro el missatge
            System.out.println("*********** MISSATGE ENCRIPTAT ***********");
            byte[] xifrat = Xifrar.encryptA5(missatge.getBytes(),k.getPublic());
            String sx = new String(xifrat, StandardCharsets.UTF_8);
            System.out.println(sx);

            // desxifro el missatge
            System.out.println("*********** MISSATGE DESENCRIPTAT ***********");
            byte[] desxifrat = Xifrar.decryptA5(xifrat,k.getPrivate());
            String sd = new String(desxifrat, StandardCharsets.UTF_8);
            System.out.println(sd);

            System.out.println("*********** PUBLIC KEY / PRIVATE KEY ***********");
            System.out.println(k.getPublic()); // retorna la informació de la clau publica generada
            System.out.println(k.getPrivate()); // retorna la informació de la clau privada generada

        // 1.2
        System.out.println("######################### 1.2 ##########################");
            try {
                KeyStore keyStore = Xifrar.loadKeyStore("/home/usuario/.keystore","usuario");

                System.out.println("Tipus d'emmagatzematge: " + keyStore.getType());

                System.out.println("Mida del magatzem: " + keyStore.size());

                // alias
                Enumeration<String> enumeration = keyStore.aliases();
                while(enumeration.hasMoreElements()) {
                    String alias = enumeration.nextElement();
                    System.out.println("alias name: " + alias);
                }

                System.out.println(keyStore.getCertificate("jordi"));

                char[] JavaCharArray = {'u', 's', 'u', 'a', 'r', 'i', 'o'};
                System.out.println("Tipus d'algoritme de la clau mykey: " + keyStore.getKey("mykey", JavaCharArray).getAlgorithm());

                // 1.2.2
                SecretKey sk = Xifrar.passwordKeyGeneration("pol",256);
                KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sk);
                KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(JavaCharArray);
                keyStore.setEntry("polA5", skEntry,protectionParameter);
                try (FileOutputStream fom = new FileOutputStream("/home/usuario/.keystore")) {
                    keyStore.store(fom, JavaCharArray);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        // 1.3
        System.out.println("######################### 1.3 ##########################");
            try {
                PublicKey publicKey13 = Xifrar.getPublicKey("/home/usuario/Escritorio/jordi.cer"); // /home/usuario/ex6.cer /home/usuario/Escritorio/jordi.cer
                System.out.println(publicKey13);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }

        // 1.4
        System.out.println("######################### 1.4 ##########################");
            try {
                KeyStore keyStore = Xifrar.loadKeyStore("/home/usuario/.keystore","usuario");
                PublicKey publicKey14 = Xifrar.getPublicKey4(keyStore,"mykey","usuario");
                System.out.println(publicKey14);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        // 1.5
        System.out.println("######################### 1.5 ##########################");
            String st15 = "Exercici 1.5 sdvjnsjvknjvnfjvndfkjvjndfkvjdnzvkjnfkjdvkjzdnkjnfvkjn";
            byte[] signatura = null;
            try {
                signatura = Xifrar.signData(st15.getBytes(StandardCharsets.UTF_8),k.getPrivate());
                String s15 = new String(signatura, StandardCharsets.UTF_8);
                System.out.println(s15);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }

        // 1.6
        System.out.println("######################### 1.6 ##########################");
            try {
                boolean b16 = Xifrar.validateSignature(st15.getBytes(),signatura,k.getPublic());
                System.out.println(b16);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }

        // 2.2
        System.out.println("######################### 2.2 ##########################");
            String st22 = "En un sistema de clau embolcallada (wrapped key en anglès), les dades es xifren usant una clau simètrica d’un sol ús, generada a l’atzar. Aquesta clau llavors es xifra usant la clau pública del destinatari del missatge. Finalment, s’envia al destinatari el missatge i la clau xifrades, conjuntament.";
            KeyPair keyPair22 = Xifrar.randomGenerate(1028);
            try {
                byte[][] bew = Xifrar.encryptWrappedData(st22.getBytes(StandardCharsets.UTF_8), keyPair22.getPublic());
                String s220 = new String(bew[0], StandardCharsets.UTF_8);
                System.out.println("Missatge xifrat: " + s220);
                String s221 = new String(bew[1], StandardCharsets.UTF_8);
                System.out.println("Clau xifrada: " + s221);

                byte[] bdw = Xifrar.decryptWrappedData(bew, keyPair22.getPrivate());
                String decrypted = new String(bdw,StandardCharsets.UTF_8);
                System.out.println("Missatge desxifrat: " + decrypted);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
    }
}