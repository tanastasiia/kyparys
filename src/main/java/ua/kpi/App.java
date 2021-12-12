package ua.kpi;

import com.google.common.primitives.Longs;
import ua.kpi.cipher.Kyparys256;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Collectors;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) {
        System.out.println("Hello World!");

        var rand = new Random(42);
        var sbM = new StringBuilder();
        var sbK = new StringBuilder();
        for(int i=0;i<256;i++) {
            sbM.append(rand.nextInt(2));
            sbK.append(rand.nextInt(2));
        }
        System.out.println("K: " + new BigInteger(sbK.toString(), 2).toString(16));
        System.out.println("M: " + new BigInteger(sbM.toString(), 2).toString(16));
        /*System.out.println("K: " + new BigInteger(sbK.toString(), 2).toString(2));
        System.out.println("M: " + new BigInteger(sbM.toString(), 2).toString(2));*/
        System.out.println("K: " + sbK.toString());
        System.out.println("M: " + sbM.toString());



        var kyparys = new Kyparys256();

        var keys = kyparys.getRoundKeys(sbK.toString());
     /*   for(int i=0;i< keys.length;i++) {
            System.out.println("r " + i + "  " + new BigInteger(Arrays.stream(keys[i])
                    .mapToObj(j -> String.format("%32s", Long.toBinaryString(j)).replace(' ', '0'))
                    .collect(Collectors.joining()), 2).toString(16));

            System.out.println("r " + i + "  "  + Arrays.stream(keys[i])
                    .mapToObj(j -> String.format("%32s", Long.toBinaryString(j)).replace(' ', '0'))
                    .collect(Collectors.joining()));
        }*/

        var encrypted = kyparys.encryptBlock(sbM.toString(),  keys);

        System.out.println("C: " + encrypted );
        System.out.println("C: " + new BigInteger(encrypted, 2).toString(16) + "\n");

     //   kyparys.roundsResults.forEach(System.out::println);

        var decrypted = kyparys.decryptBlock(encrypted, keys);

        System.out.println("M: " + decrypted+ "\n");


    //    kyparys.roundsResults.forEach(System.out::println);



    }
}
