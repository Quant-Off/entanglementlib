/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
