package ua.kpi;

import ua.kpi.cipher.Kyparys256;

import java.util.Random;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) {
        System.out.println("Hello World!");

        var rand = new Random();
        var sbM = new StringBuilder();
        var sbK = new StringBuilder();
        for(int i=0;i<256;i++) {
            sbM.append(rand.nextInt(2));
            sbK.append(rand.nextInt(2));
        }

        System.out.println("K: " + sbK.toString());
        System.out.println("M: " + sbM.toString());


        var kyparys = new Kyparys256();

        var keys = kyparys.getRoundKeys(sbK.toString());

        var encrypted = kyparys.encryptBlock(sbM.toString(),  keys);

        System.out.println("C: " + encrypted);

        var decrypted = kyparys.decryptBlock(encrypted, keys);

        System.out.println("M: " + decrypted);



    }
}
