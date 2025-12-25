/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
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

    AES256("AES", CryptoMethod.SYMMETRIC),

    CHACHA20("ChaCha20", CryptoMethod.STREAM),
    CHACHA20_POLY1305("ChaCha20-Poly1305", CryptoMethod.STREAM);

    private final String algorithmName;
    private final CryptoMethod method;

    ClassicalType(String algorithmName, CryptoMethod method) {
        this.method = method;
        this.algorithmName = algorithmName;
    }

    public static Optional<ClassicalType> fromName(final @NotNull String name) {
        return Arrays.stream(ClassicalType.values())
                .filter(type -> name.trim().equalsIgnoreCase(type.getAlgorithmName()))
                .filter(type -> type.getAlgorithmName().length() == name.length())
                .findFirst();
    }
}
