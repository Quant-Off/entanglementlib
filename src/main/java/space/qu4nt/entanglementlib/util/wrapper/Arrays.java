/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.wrapper;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
public final class Arrays {

    public static byte[] concatenate(byte[][] bytes2d) {
        return org.bouncycastle.util.Arrays.concatenate(bytes2d);
    }

    public static byte[] concatenate(byte[] bytes, byte[] bytes1) {
        return org.bouncycastle.util.Arrays.concatenate(bytes, bytes1);
    }

    public static byte[] concatenate(byte[] bytes, byte[] bytes1, byte[] bytes2) {
        return org.bouncycastle.util.Arrays.concatenate(bytes, bytes1, bytes2);
    }

    public static byte[] concatenate(byte[] bytes, byte[] bytes1, byte[] bytes2, byte[] bytes3) {
        return org.bouncycastle.util.Arrays.concatenate(bytes, bytes1, bytes2, bytes3);
    }

    public static int[] concatenate(int[] ints, int[] ints1) {
        return org.bouncycastle.util.Arrays.concatenate(ints, ints1);
    }

    public static short[] concatenate(short[] shorts, short[] shorts1) {
        return org.bouncycastle.util.Arrays.concatenate(shorts, shorts1);
    }
}
