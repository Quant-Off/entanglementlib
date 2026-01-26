/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.ProgressResult;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;
import space.qu4nt.entanglementlib.exception.critical.EntLibSecurityError;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoKEMProcessingException;
import space.qu4nt.entanglementlib.security.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.ParameterSizeDetail;
import space.qu4nt.entanglementlib.security.crypto.bundle.MLKEMStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeKEMStrategy;

/// @author Q. T. Felix
/// @since 1.1.0
@Slf4j
public final class MLKEMStrategy implements NativeKEMStrategy {

    private final KEMType type;

    MLKEMStrategy(@NotNull KEMType type) {
        this.type = type;
    }

    /// MLKEMStrategy 인스턴스를 생성합니다.
    ///
    /// 주의하세요! 이 메소드를 사용하여 전략 패턴을 선언하는 것은 올바르지 않습니다.
    /// 이 메소드는 [EntLibCryptoRegistry] 레지스트리에 등록할 때 사용되는
    /// 메소드입니다.
    ///
    /// @param type ML-KEM 타입
    /// @return 새 MLKEMStrategy 인스턴스
    @ApiStatus.Internal
    public static MLKEMStrategy create(@NotNull KEMType type) {
        return new MLKEMStrategy(type);
    }

    @Override
    public SensitiveDataContainer encapsulate(@NotNull SensitiveDataContainer keyPublic)
            throws EntLibCryptoKEMProcessingException, EntLibSecureIllegalStateException {
        ParameterSizeDetail detail = type.getParameterSizeDetail();
        if (keyPublic.getMemorySegment().byteSize() != detail.getEncapsulationKeySize())
            throw new EntLibCryptoKEMProcessingException(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );
        SensitiveDataContainer ssContainer = new SensitiveDataContainer(detail.getSharedSecretKeySize());
        SensitiveDataContainer ctContainer = ssContainer.addContainerData(detail.getCiphertextSize());
        try {
            final ProgressResult result = ProgressResult.fromCode((int) MLKEMStrategyBundle
                    .callNativeMLKEMHandle(type, 1) // encap type
                    .invokeExact(
                            ctContainer.getMemorySegment(),
                            ssContainer.getMemorySegment(),
                            keyPublic.getMemorySegment()
                    ));
            if (result.isFail())
                throw new EntLibCryptoKEMProcessingException("키 캡슐화에 실패했습니다! 네이티브 코드 반환값: " + result.getCode());
        } catch (Throwable e) {
            ssContainer.close();
            throw new EntLibNativeError("네이티브 에러", e);
        }
        return ssContainer;
    }

    @Override
    public SensitiveDataContainer decapsulate(@NotNull SensitiveDataContainer secretKeyContainer, @NotNull SensitiveDataContainer ciphertext) {
        ParameterSizeDetail detail = type.getParameterSizeDetail();
        if (ciphertext.getMemorySegment().byteSize() != detail.getCiphertextSize())
            throw new EntLibSecurityError(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );

        SensitiveDataContainer ssContainer = new SensitiveDataContainer(detail.getSharedSecretKeySize());
        try {
            final ProgressResult result = ProgressResult.fromCode((int) MLKEMStrategyBundle
                    .callNativeMLKEMHandle(type, 2) // decap type
                    .invokeExact(
                            ssContainer.getMemorySegment(),
                            ciphertext.getMemorySegment(),
                            secretKeyContainer.getMemorySegment()
                    ));
            if (result.isFail()) {
                throw new EntLibCryptoKEMProcessingException("키 디캡슐화에 실패했습니다! 네이티브 코드 반환값: " + result.getCode());
            }
        } catch (Throwable e) {
            ssContainer.close();
            throw new EntLibNativeError("네이티브 에러", e);
        }
        return ssContainer;
    }

    @Override
    public String getAlgorithmName() {
        return "ML-KEM";
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return type;
    }
}