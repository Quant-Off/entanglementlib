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

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;

import java.util.Arrays;
import java.util.Optional;

/**
 * 고전 암호화 알고리즘의 유형을 정의하는 열거형 클래스입니다.
 * 각 유형은 알고리즘 이름과 함께 고유한 식별자를 가집니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Getter
public enum ClassicalType implements EntLibParameterSpec {

    RSA1024("RSA", CryptoMethod.ASYMMETRIC),
    RSA2048("RSA", CryptoMethod.ASYMMETRIC),
    RSA4096("RSA", CryptoMethod.ASYMMETRIC),

    AES128("AES", CryptoMethod.SYMMETRIC),
    AES192("AES", CryptoMethod.SYMMETRIC),
    AES256("AES", CryptoMethod.SYMMETRIC),

    CHACHA20("ChaCha20", CryptoMethod.STREAM),
    CHACHA20_POLY1305("ChaCha20-Poly1305", CryptoMethod.STREAM);

    private String algorithmName;
    private final CryptoMethod method;

    ClassicalType(String algorithmName, CryptoMethod method) {
        this.method = method;
        this.algorithmName = algorithmName;
    }

    public void fixAlgorithmName(final String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public static Optional<ClassicalType> fromName(final @NotNull String name) {
        return Arrays.stream(ClassicalType.values())
                .filter(type -> name.trim().equalsIgnoreCase(type.getAlgorithmName()))
                .filter(type -> type.getAlgorithmName().length() == name.length())
                .findFirst();
    }
}
