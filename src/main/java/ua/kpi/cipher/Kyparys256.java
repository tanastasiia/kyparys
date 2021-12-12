package ua.kpi.cipher;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.ObjectArrays;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Kyparys256 {
    private final int blockSize = 256;
    private final int keySize = 256;
    private final int wordSize = 32;
    private final int iterations = 10;

    private final int r0 = 16;
    private final int r1 = 12;
    private final int r2 = 8;
    private final int r3 = 7;

    private final long tmv0 = 0x000F000FL;
    private final long tmv1 = 0x000F000FL;
    private final long tmv2 = 0x000F000FL;
    private final long tmv3 = 0x000F000FL;

    private final long mask32 = (1L << 32L) - 1L;

    public long[][] getRoundKeys(String key) {
        var RK = new long[iterations][4];
        var tmv = new long[]{tmv0, tmv1, tmv2, tmv3};

        var K = split(key).stream().mapToLong(s -> Long.parseLong(s, 2)).toArray();
        var KL = ArrayUtils.subarray(K, 0, 4);
        var KR = ArrayUtils.subarray(K, 4, 8);

        //get K sigma
        var ones = new long[]{1L, 1L, 1L, 1L};
        var st = xor(ones, KL);
        st = h(st[0], st[1], st[2], st[3]);
        st = h(st[0], st[1], st[2], st[3]);
        st = add(st, KR);
        st = h(st[0], st[1], st[2], st[3]);
        st = h(st[0], st[1], st[2], st[3]);
        st = xor(st, KL);
        var Ksigma = st;

        //get Round keys
        for (int i = 0; i < iterations / 2; i++) {

            KL = ArrayUtils.subarray(K, 0, 4);
            KR = ArrayUtils.subarray(K, 4, 8);

            //1 get even round ket
            st = KL;
            var KT = add(Ksigma, tmv);
            st = add(st, KT);
            st = h(st[0], st[1], st[2], st[3]);
            st = h(st[0], st[1], st[2], st[3]);

            st = xor(st, KT);
            st = h(st[0], st[1], st[2], st[3]);
            st = h(st[0], st[1], st[2], st[3]);

            st = add(st, KT);
            RK[2 * i] = st;

            // get odd round key
            tmv = shiftLeft(tmv, 1);
            st = KR;
            KT = add(Ksigma, tmv);

            st = add(st, KT);
            st = h(st[0], st[1], st[2], st[3]);
            st = h(st[0], st[1], st[2], st[3]);

            st = xor(st, KT);
            st = h(st[0], st[1], st[2], st[3]);
            st = h(st[0], st[1], st[2], st[3]);

            st = add(st, KT);
            RK[2 * i + 1] = st;

            tmv = shiftLeft(tmv, 1);

            K = rotlKey1(K);

        }

        return RK;


    }

    public String encryptBlock(String bitSequence, long[][] roundKeys) {

        var M = split(bitSequence);

        var L = M.subList(0, 4).stream().mapToLong(s -> Long.parseLong(s, 2)).toArray();
        var R = M.subList(4, 8).stream().mapToLong(s -> Long.parseLong(s, 2)).toArray();

        for (int i = 0; i < iterations; i++) {
            var temp = L;
            var K = roundKeys[i];
            L = xor(R, f(L, K));
            R = temp;
        }

        return Arrays.stream(Longs.concat(R, L))
                .mapToObj(i -> String.format("%32s", Long.toBinaryString(i)).replace(' ', '0'))
                .collect(Collectors.joining());

    }

    public String decryptBlock(String bitSequence, long[][] roundKeys) {
        ArrayUtils.reverse(roundKeys);

        return encryptBlock(bitSequence, roundKeys);

    }

    private long[] f(long[] L, long[] K) {
        long P0 = add(L[0], K[0]);
        long P1 = add(L[1], K[1]);
        long P2 = add(L[2], K[2]);
        long P3 = add(L[3], K[3]);

        var h1 = h(P0, P1, P2, P3);
        return h(h1[0], h1[1], h1[2], h1[3]);
    }

    private long[] h(long P0, long P1, long P2, long P3) {
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

        return new long[]{P0, P1, P2, P3};
    }

    private List<String> split(String sequence) {
        return Lists.newArrayList(Splitter.fixedLength(8).split(sequence));
    }

    public long rotl(long x, long r) {
        return ((x << r) & mask32) + (x >> (wordSize - r));
    }

    private long add(long x, long y) {
        return (x + y) & mask32;
    }

    private long xor(long x, long y) {
        return x ^ y;
    }

    private long[] xor(long[] a, long[] b) {
        long[] c = new long[a.length];
        for (int i = 0; i < a.length; i++) {
            c[i] = a[i] ^ b[i];
        }
        return c;
    }

    private long[] add(long[] a, long[] b) {
        long[] c = new long[a.length];
        for (int i = 0; i < a.length; i++) {
            c[i] = add(a[i], b[i]);
        }
        return c;
    }

    private long[] shiftLeft(long[] a, int r) {
        long[] c = new long[a.length];
        for (int i = 0; i < a.length; i++) {
            c[i] = (a[i] << r) & mask32;
        }
        return c;
    }

    private long[] rotlKey1(long[] a) {
        var c = new long[a.length];
        System.arraycopy(a, 1, c, 0, a.length - 1);
        c[c.length - 1] = a[0];
        return c;
    }
}
