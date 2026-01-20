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

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.util.Nill;

/**
 * 메시지 인증 코드 알고리즘을 정의하고 결정론적 결과를 도출하는 기능을 제공하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
@Getter
@ApiStatus.Experimental
public final class Mac extends EntLibAlgorithm<EntLibSecretKey> {

    public static final Mac HmacSHA1 = new Mac("HmacSHA1");
    public static final Mac HmacSHA224 = new Mac("HmacSHA224");
    public static final Mac HmacSHA256 = new Mac("HmacSHA256");
    public static final Mac HmacSHA384 = new Mac("HmacSHA384");
    public static final Mac HmacSHA512 = new Mac("HmacSHA512");
    public static final Mac HmacSHA512variant224 = new Mac("HmacSHA512/224");
    public static final Mac HmacSHA512variant256 = new Mac("HmacSHA512/256");

    public static final Mac HmacSHA3_224 = new Mac("HmacSHA3-224");
    public static final Mac HmacSHA3_256 = new Mac("HmacSHA3-256");
    public static final Mac HmacSHA3_384 = new Mac("HmacSHA3-384");
    public static final Mac HmacSHA3_512 = new Mac("HmacSHA3-512");

    public static final Mac HmacPBESHA1 = new Mac("HmacPBESHA1");
    public static final Mac HmacPBESHA224 = new Mac("HmacPBESHA224");
    public static final Mac HmacPBESHA256 = new Mac("HmacPBESHA256");
    public static final Mac HmacPBESHA384 = new Mac("HmacPBESHA384");
    public static final Mac HmacPBESHA512 = new Mac("HmacPBESHA512");
    public static final Mac HmacPBESHA512variant224 = new Mac("HmacPBESHA512/224");
    public static final Mac HmacPBESHA512variant256 = new Mac("HmacPBESHA512/256");

    public static final Mac PBEWithHmacSHA1 = new Mac("PBEWithHmacSHA1");
    public static final Mac PBEWithHmacSHA224 = new Mac("PBEWithHmacSHA224");
    public static final Mac PBEWithHmacSHA256 = new Mac("PBEWithHmacSHA256");
    public static final Mac PBEWithHmacSHA384 = new Mac("PBEWithHmacSHA384");
    public static final Mac PBEWithHmacSHA512 = new Mac("PBEWithHmacSHA512");
    public static final Mac PBEWithHmacSHA512variant224 = new Mac("PBEWithHmacSHA512/224");
    public static final Mac PBEWithHmacSHA512variant256 = new Mac("PBEWithHmacSHA512/256");

    private String macAlgorithm;

    private Mac(String keyGenerateAlgorithm, @Nullable String macAlgorithm) {
        super(EntLibSecretKey.class, keyGenerateAlgorithm, 0, false);
        this.macAlgorithm = Nill.nullDef(macAlgorithm, () -> keyGenerateAlgorithm);
    }

    private Mac(String keyGenerateAlgorithm) {
        this(keyGenerateAlgorithm, null);
    }

    /**
     * 메시지 인증 코드(MAC) 알고리즘을 변경하는 메소드입니다.
     *
     * @param algorithm 사용할 MAC 알고리즘
     * @return 인스턴스 반영된 {@link Mac}
     */
    public Mac changeMACAlgorithm(@NotNull String algorithm) {
        this.macAlgorithm = algorithm;
        return this;
    }

}
