/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.wrapper;

import java.math.BigInteger;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
public final class Arrays {

    public static byte[] concatenate(byte[] a, byte[] b) {
        if (null == a) {
            // b might also be null
            return clone(b);
        }
        if (null == b) {
            // a might also be null
            return clone(a);
        }

        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public static short[] concatenate(short[] a, short[] b) {
        if (null == a) {
            // b might also be null
            return clone(b);
        }
        if (null == b) {
            // a might also be null
            return clone(a);
        }

        short[] r = new short[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c) {
        if (null == a) {
            return concatenate(b, c);
        }
        if (null == b) {
            return concatenate(a, c);
        }
        if (null == c) {
            return concatenate(a, b);
        }

        byte[] r = new byte[a.length + b.length + c.length];
        int pos = 0;
        System.arraycopy(a, 0, r, pos, a.length);
        pos += a.length;
        System.arraycopy(b, 0, r, pos, b.length);
        pos += b.length;
        System.arraycopy(c, 0, r, pos, c.length);
        return r;
    }

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d) {
        if (null == a) {
            return concatenate(b, c, d);
        }
        if (null == b) {
            return concatenate(a, c, d);
        }
        if (null == c) {
            return concatenate(a, b, d);
        }
        if (null == d) {
            return concatenate(a, b, c);
        }

        byte[] r = new byte[a.length + b.length + c.length + d.length];
        int pos = 0;
        System.arraycopy(a, 0, r, pos, a.length);
        pos += a.length;
        System.arraycopy(b, 0, r, pos, b.length);
        pos += b.length;
        System.arraycopy(c, 0, r, pos, c.length);
        pos += c.length;
        System.arraycopy(d, 0, r, pos, d.length);
        return r;
    }

    public static byte[] concatenate(byte[][] arrays) {
        int size = 0;
        for (int i = 0; i != arrays.length; i++) {
            size += arrays[i].length;
        }

        byte[] rv = new byte[size];

        int offSet = 0;
        for (int i = 0; i != arrays.length; i++) {
            System.arraycopy(arrays[i], 0, rv, offSet, arrays[i].length);
            offSet += arrays[i].length;
        }

        return rv;
    }

    public static int[] concatenate(int[] a, int[] b) {
        if (null == a) {
            // b might also be null
            return clone(b);
        }
        if (null == b) {
            // a might also be null
            return clone(a);
        }

        int[] r = new int[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public static boolean[] clone(boolean[] data) {
        return null == data ? null : data.clone();
    }

    public static byte[] clone(byte[] data) {
        return null == data ? null : data.clone();
    }

    public static char[] clone(char[] data) {
        return null == data ? null : data.clone();
    }

    public static int[] clone(int[] data) {
        return null == data ? null : data.clone();
    }

    public static long[] clone(long[] data) {
        return null == data ? null : data.clone();
    }

    public static short[] clone(short[] data) {
        return null == data ? null : data.clone();
    }

    public static BigInteger[] clone(BigInteger[] data) {
        return null == data ? null : data.clone();
    }

    public static byte[] clone(byte[] data, byte[] existing) {
        if (data == null) {
            return null;
        }
        if ((existing == null) || (existing.length != data.length)) {
            return clone(data);
        }
        System.arraycopy(data, 0, existing, 0, existing.length);
        return existing;
    }

    public static long[] clone(long[] data, long[] existing) {
        if (data == null) {
            return null;
        }
        if ((existing == null) || (existing.length != data.length)) {
            return clone(data);
        }
        System.arraycopy(data, 0, existing, 0, existing.length);
        return existing;
    }

    public static byte[][] clone(byte[][] data) {
        if (data == null) {
            return null;
        }

        byte[][] copy = new byte[data.length][];

        for (int i = 0; i != copy.length; i++) {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static byte[][][] clone(byte[][][] data) {
        if (data == null) {
            return null;
        }

        byte[][][] copy = new byte[data.length][][];

        for (int i = 0; i != copy.length; i++) {
            copy[i] = clone(data[i]);
        }

        return copy;
    }
}
