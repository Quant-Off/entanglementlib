/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/// 파라미터의 데이터 바이트 사이즈를 관리할 수 있는 클래스입니다.
/// 기존 키 사이즈를 정수 배열로 관리하는 방식에서 변경되었습니다.
///
/// 이 클래스는 읽기 전용 클래스로, [ParameterSizeDetailBuilder]
/// 빌더 패턴을 사용하여 쓰기 작업 후 사용할 수 있습니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ParameterSizeDetail {

    // Symmetric
    private int secretKeySize;

    // Asymmetric
    private int publicKeySize;
    private int privateKeySize;

    // Signature
    private int signatureSize;

    // KEM, etc
    private int encapsulationKeySize;
    private int decapsulationKeySize;
    private int ciphertextSize;
    private int sharedSecretKeySize;

    private ParameterSizeDetail(int secretKeySize) {
        this.secretKeySize = secretKeySize;
    }

    public ParameterSizeDetail(int publicKeySize, int privateKeySize) {
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
    }

    public ParameterSizeDetail(int publicKeySize, int privateKeySize, int signatureSize) {
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.signatureSize = signatureSize;
    }

    public ParameterSizeDetail(int encapsulationKeySize, int decapsulationKeySize, int ciphertextSize, int sharedSecretKeySize) {
        this.encapsulationKeySize = encapsulationKeySize;
        this.decapsulationKeySize = decapsulationKeySize;
        this.ciphertextSize = ciphertextSize;
        this.sharedSecretKeySize = sharedSecretKeySize;
    }

    public static ParameterSizeDetail symmetric(int secretKeySize) {
        return new ParameterSizeDetail(secretKeySize);
    }

    public static ParameterSizeDetail asymmetric(int publicKeySize, int privateKeySize) {
        return new ParameterSizeDetail(publicKeySize, privateKeySize);
    }

    public static ParameterSizeDetail sign(int publicKeySize, int privateKeySize, int signatureSize) {
        return new ParameterSizeDetail(publicKeySize, privateKeySize, signatureSize);
    }

    public static ParameterSizeDetail kem(int encapsulationKeySize, int decapsulationKeySize, int ciphertextSize, int sharedSecretKeySize) {
        return new ParameterSizeDetail(encapsulationKeySize, decapsulationKeySize, ciphertextSize, sharedSecretKeySize);
    }

    public static ParameterSizeDetail empty() {
        return new ParameterSizeDetail();
    }

    public ParameterSizeDetail secretKeySize(int value) {
        this.secretKeySize = value;
        return this;
    }

    public ParameterSizeDetail publicKeySize(int value) {
        this.publicKeySize = value;
        return this;
    }

    public ParameterSizeDetail privateKeySize(int value) {
        this.privateKeySize = value;
        return this;
    }

    public ParameterSizeDetail signatureSize(int value) {
        this.signatureSize = value;
        return this;
    }

    public ParameterSizeDetail encapsulationKeySize(int value) {
        this.encapsulationKeySize = value;
        return this;
    }

    public ParameterSizeDetail decapsulationKeySize(int value) {
        this.decapsulationKeySize = value;
        return this;
    }

    public ParameterSizeDetail ciphertextSize(int value) {
        this.ciphertextSize = value;
        return this;
    }

    public ParameterSizeDetail sharedSecretKeySize(int value) {
        this.sharedSecretKeySize = value;
        return this;
    }
}
