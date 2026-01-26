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
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoSignatureProcessingException;
import space.qu4nt.entanglementlib.security.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.ParameterSizeDetail;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;
import space.qu4nt.entanglementlib.security.crypto.bundle.MLDSAStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeSignatureStrategy;

import java.util.Optional;

/// # Memo
///
/// 네이티브 연동 후 pqc 알고리즘 수행에 있어 생명주기를 다음과 같이 명심해야 함.
///
/// 1. 키 페어 생성
///    - 키 페어는 서명 및 검증 작업이 완료된 이후에 소거되어야 함.
/// 2. 서명
///    - 서명 시 `평문(TBSData)`을 최초로 받음. 다만 서명이 완료되어도 평문은 검증에 사용되기 때문에 이 시점에 소거되어선 안 됨.
///    - 서명이 완료된 후 메모리에 잔류하는 비밀 키 데이터 모두 소거.
///    - 서명이 완료되어 통신 상대방에게 서명을 전달하고 사용자가 정상적으로 받은 경우에 서버 측에 잔류하는 서명 데이터 소거.
/// 3. 검증
///    - 상대방이 자신의 공개 키와 평문으로 서명을 검증 완료하면 평문 소거.
///
/// 평문의 경우 Java에서 바이트 배열로 받기 때문에, [SensitiveDataContainer]에 평문 넘기면 평문이 위치한 heap은 자동으로 소거됨.
/// 현재 heap 메모리에 남은 데이터를 지우고 난 뒤, 메모리 구역을 만들어 Rust 로 넘기는 방식임.
///
/// @author Q. T. Felix
/// @since 1.1.0
@Slf4j
public final class MLDSAStrategy implements NativeSignatureStrategy {

    private final SignatureType type;

    MLDSAStrategy(@NotNull SignatureType type) {
        this.type = type;
    }

    /// MLDSAStrategy 인스턴스를 생성합니다.
    ///
    /// 주의하세요! 이 메소드를 사용하여 전략 패턴을 선언하는 것은 올바르지 않습니다.
    /// 이 메소드는 [EntLibCryptoRegistry] 레지스트리에 등록할 때 사용되는
    /// 메소드입니다.
    ///
    /// @param type SignatureType (ML_DSA_44, ML_DSA_65, ML_DSA_87)
    /// @return 새 MLDSAStrategy 인스턴스
    @ApiStatus.Internal
    public static MLDSAStrategy create(@NotNull SignatureType type) {
        return new MLDSAStrategy(type);
    }

    @Override
    public SensitiveDataContainer sign(@NotNull SensitiveDataContainer keyPrivate, byte[] plainBytes)
            throws EntLibCryptoSignatureProcessingException, EntLibSecureIllegalStateException {
        ParameterSizeDetail detail = type.getParameterSizeDetail();
        if (keyPrivate.getMemorySegment().byteSize() != detail.getPrivateKeySize())
            throw new EntLibSecurityError(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );
        SensitiveDataContainer complexContainer = new SensitiveDataContainer(detail.getSignatureSize());
        SensitiveDataContainer plain = complexContainer.addContainerData(plainBytes, true);
        try {
            final ProgressResult result = ProgressResult.fromCode((int) MLDSAStrategyBundle
                    .callNativeMLDSAHandle(type, 1) // sign type
                    .invokeExact(
                            complexContainer.getMemorySegment(),
                            plain.getMemorySegment(),
                            (long) plainBytes.length,
                            keyPrivate.getMemorySegment()));
            if (result.isFail())
                throw new EntLibCryptoSignatureProcessingException("서명에 실패했습니다! 네이티브 코드 반환값: " + result.getCode());
        } catch (Throwable e) {
            complexContainer.close();
            throw new EntLibNativeError("네이티브 에러", e);
        }
        // 서명 완료 후 공개 키를 컨테이너 추가
        return complexContainer;
    }

    @Override
    public boolean verify(@NotNull SensitiveDataContainer container)
            throws EntLibCryptoSignatureProcessingException {
        ParameterSizeDetail detail = type.getParameterSizeDetail();
        // 평문
        Optional<SensitiveDataContainer> plainOpt = container.get(0);
        if (plainOpt.isEmpty())
            throw new EntLibCryptoSignatureProcessingException("평문 컨테이너가 존재하지 않습니다!");
        SensitiveDataContainer plain = plainOpt.get();

        // 공개 키
        Optional<SensitiveDataContainer> pkOpt = container.get(1);
        if (pkOpt.isEmpty())
            throw new EntLibCryptoSignatureProcessingException("공개 키 컨테이너가 존재하지 않습니다!");
        SensitiveDataContainer keyPublic = pkOpt.get();

        if (container.getMemorySegment().byteSize() != detail.getSignatureSize() ||
                keyPublic.getMemorySegment().byteSize() != detail.getPublicKeySize())
            throw new EntLibSecurityError(
                    "일부 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 또는 인프라에 중간자 공격 또는 패킷 탈취 등의 악의적인 공격을 예상할 수 있습니다."
            );

        try {
            final ProgressResult result = ProgressResult.fromCode((int) MLDSAStrategyBundle
                    .callNativeMLDSAHandle(type, 2) // verify type
                    .invokeExact(
                            plain.getMemorySegment(),
                            plain.getMemorySegment().byteSize(),
                            container.getMemorySegment(),
                            keyPublic.getMemorySegment()));
            if (result.isFail())
                throw new EntLibCryptoSignatureProcessingException("서명 검증에 실패했습니다! 네이티브 코드 반환값: " + result.getCode());
            return true;
        } catch (Throwable e) {
            throw new EntLibNativeError("네이티브 에러", e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return "ML-DSA";
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return type;
    }
}