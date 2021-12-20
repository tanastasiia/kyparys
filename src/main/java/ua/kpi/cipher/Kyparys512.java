package ua.kpi.cipher;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class Kyparys512 {
    private final int blockSize = 512;
    private final int keySize = 512;
    private final int wordSize = 64;
    private final int iterations = 14;

    private final int r0 = 32;
    private final int r1 = 24;
    private final int r2 = 16;
    private final int r3 = 15;

    private final BigInteger tmv0 = BigInteger.valueOf(0x000F000FL);
    private final BigInteger tmv1 = BigInteger.valueOf(0x000F000FL);
    private final BigInteger tmv2 = BigInteger.valueOf(0x000F000FL);
    private final BigInteger tmv3 = BigInteger.valueOf(0x000F000FL);

    private final BigInteger mask64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    public List<List<BigInteger>> getRoundKeys(String key) {
        var RK = new ArrayList<List<BigInteger>>(iterations);
        for (int i = 0; i < iterations; i++) {
            RK.add(new ArrayList<>());
        }
        var tmv = Arrays.asList(tmv0, tmv1, tmv2, tmv3);

        var K = split(key).stream().map(s -> new BigInteger(s, 2)).collect(Collectors.toList());
        var KL = K.subList(0, 4);
        var KR = K.subList(4, 8);

        //get K sigma
        var ones = Arrays.asList(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE);
        var st = xor(ones, KL);

        st = h(st.get(0), st.get(1), st.get(2), st.get(3));
        st = h(st.get(0), st.get(1), st.get(2), st.get(3));
        st = add(st, KR);
        st = h(st.get(0), st.get(1), st.get(2), st.get(3));
        st = h(st.get(0), st.get(1), st.get(2), st.get(3));
        st = xor(st, KL);
        var Ksigma = st;

        //get Round keys
        for (int i = 0; i < iterations / 2; i++) {


            KL = K.subList(0, 4);
            KR = K.subList(4, 8);

            //1 get even round ket
            st = KL;
            var KT = add(Ksigma, tmv);
            st = add(st, KT);
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));

            st = xor(st, KT);
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));

            st = add(st, KT);
            RK.set(2 * i, st);

            // get odd round key
            tmv = shiftLeftBits(tmv, 1);
            st = KR;
            KT = add(Ksigma, tmv);

            st = add(st, KT);
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));

            st = xor(st, KT);
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));
            st = h(st.get(0), st.get(1), st.get(2), st.get(3));

            st = add(st, KT);
            RK.set(2 * i + 1, st);

            tmv = shiftLeftBits(tmv, 1);

            K = rotlKey1Words(K);

        }

        return RK;

    }

    public String encryptBlock(String bitSequence, List<List<BigInteger>> roundKeys) {

        var M = split(bitSequence);

        var L = M.subList(0, 4).stream().map(s -> new BigInteger(s, 2)).collect(Collectors.toList());
        var R = M.subList(4, 8).stream().map(s -> new BigInteger(s, 2)).collect(Collectors.toList());

        for (int i = 0; i < iterations; i++) {
            var temp = L;
            var K = roundKeys.get(i);
            L = xor(R, f(L, K));
            R = temp;
        }
        R.addAll(L);
        return R.stream()
                .map(i -> String.format("%64s", i.toString(2)).replace(' ', '0'))
                .collect(Collectors.joining());

    }

    public String decryptBlock(String bitSequence, List<List<BigInteger>> roundKeys) {
        Collections.reverse(roundKeys);
        return encryptBlock(bitSequence, roundKeys);

    }

    private List<BigInteger> f(List<BigInteger> L, List<BigInteger> K) {
        BigInteger P0 = xor(L.get(0), K.get(0));
        BigInteger P1 = xor(L.get(1), K.get(1));
        BigInteger P2 = xor(L.get(2), K.get(2));
        BigInteger P3 = xor(L.get(3), K.get(3));

        var h1 = h(P0, P1, P2, P3);
        return h(h1.get(0), h1.get(1), h1.get(2), h1.get(3));
    }

    private List<BigInteger> h(BigInteger P0, BigInteger P1, BigInteger P2, BigInteger P3) {
        P0 = add(P0, P1);
        P3 = xor(P3, P0);
        P3 = rotl(P3, r0);

        P2 = add(P2, P3);
        P1 = xor(P1, P2);
        P1 = rotl(P1, r1);

        P0 = add(P0, P1);
        P3 = xor(P3, P0);
        P3 = rotl(P3, r2);

        P2 = add(P2, P3);
        P1 = xor(P1, P2);
        P1 = rotl(P1, r3);

        return Arrays.asList(P0, P1, P2, P3);
    }

    private List<String> split(String sequence) {
        List<String> res = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            res.add(sequence.substring(i * wordSize, wordSize * i + wordSize));
        }
        return res;
    }

    public BigInteger rotl(BigInteger x, int r) {
        return x.shiftLeft(r).and(mask64).add(x.shiftRight(wordSize - r));
    }

    private BigInteger add(BigInteger x, BigInteger y) {
        return x.add(y).and(mask64);
    }

    private BigInteger xor(BigInteger x, BigInteger y) {
        return x.xor(y);
    }

    private List<BigInteger> xor(List<BigInteger> a, List<BigInteger> b) {
        var c = new ArrayList<BigInteger>();
        for (int i = 0; i < a.size(); i++) {
            c.add(a.get(i).xor(b.get(i)));
        }
        return c;
    }

    private List<BigInteger> add(List<BigInteger> a, List<BigInteger> b) {
        var c = new ArrayList<BigInteger>();
        for (int i = 0; i < a.size(); i++) {
            c.add(add(a.get(i), b.get(i)));
        }
        return c;
    }

    private List<BigInteger> shiftLeftBits(List<BigInteger> a, int r) {
        var c = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : a) {
            c.add(bigInteger.shiftLeft(r).and(mask64));
        }
        return c;
    }

    private List<BigInteger> rotlKey1Words(List<BigInteger> a) {
        var c = new ArrayList<>(a.subList(1, a.size()));
        c.add(a.get(0));
        return c;
    }
}
