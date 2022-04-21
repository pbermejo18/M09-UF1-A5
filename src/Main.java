import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws UnsupportedEncodingException {
        Scanner scanner = new Scanner(System.in);
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
    }
}