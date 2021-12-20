package ua.kpi;

import ua.kpi.cipher.Kyparys256;
import ua.kpi.cipher.Kyparys512;

import java.util.Random;

public class App {


    public static void test256() {
        var rand = new Random(42);
        var sbM = new StringBuilder();
        var sbK = new StringBuilder();
        for (int i = 0; i < 256; i++) {
            sbM.append(rand.nextInt(2));
            sbK.append(rand.nextInt(2));
        }
        System.out.println("Key:               " + sbK.toString());
        System.out.println("Message:           " + sbM.toString());


        var kyparys = new Kyparys256();
        var keys = kyparys.getRoundKeys(sbK.toString());

        var encrypted = kyparys.encryptBlock(sbM.toString(), keys);
        System.out.println("Ciphertext:        " + encrypted);

        var decrypted = kyparys.decryptBlock(encrypted, keys);
        System.out.println("Message decrypted: " + decrypted);

        System.out.println("Equals: " + decrypted.equals(sbM.toString()) + "\n");

    }

    public static void test512() {
        var rand = new Random(42);
        var sbM = new StringBuilder();
        var sbK = new StringBuilder();
        for (int i = 0; i < 512; i++) {
            sbM.append(rand.nextInt(2));
            sbK.append(rand.nextInt(2));
        }
        System.out.println("Key:               " + sbK.toString());
        System.out.println("Message:           " + sbM.toString());


        var kyparys = new Kyparys512();
        var keys = kyparys.getRoundKeys(sbK.toString());

        var encrypted = kyparys.encryptBlock(sbM.toString(), keys);
        System.out.println("Ciphertext:        " + encrypted);

        var decrypted = kyparys.decryptBlock(encrypted, keys);
        System.out.println("Message decrypted: " + decrypted);

        System.out.println("Equals: " + decrypted.equals(sbM.toString()) + "\n");

    }


    public static void main(String[] args) {
        test256();
        test512();

    }
}
