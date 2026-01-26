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
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoKEMProcessingException;
import space.qu4nt.entanglementlib.security.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.bundle.X25519StrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeECDHStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeKEMStrategy;

/// X25519 Diffie-Hellman 키 교환을 KEM 스타일로 래핑한 전략 클래스입니다.
///
/// X25519는 전통적인 KEM이 아니지만, 임시 키페어 생성과 DH 연산을 통해
/// KEM과 유사한 인터페이스로 사용할 수 있습니다.
///
/// - encapsulate: 임시 키페어 생성 후 수신자 공개키와 DH 수행
/// - decapsulate: 자신의 비밀키와 상대방 임시 공개키로 DH 수행
///
/// @author Q. T. Felix
/// @since 1.1.0
@Slf4j
public final class X25519Strategy implements NativeKEMStrategy, NativeECDHStrategy {
    // TODO: 키 유도 관련 로직 추가

    static final int _SK_SIZE = 0x20;
    static final int _PK_SIZE = 0x20;
    static final int _CT_SIZE = 0x20;
    static final int _SS_SIZE = 0x20;

    private final KEMType type = KEMType.X25519;

    X25519Strategy() {
    }

    /// X25519Strategy 인스턴스를 생성합니다.
    ///
    /// 주의하세요! 이 메소드를 사용하여 전략 패턴을 선언하는 것은 올바르지 않습니다.
    /// 이 메소드는 [EntLibCryptoRegistry] 레지스트리에 등록할 때 사용되는
    /// 메소드입니다.
    ///
    /// @return 새 X25519Strategy 인스턴스
    @ApiStatus.Internal
    public static X25519Strategy create() {
        return new X25519Strategy();
    }

    /// X25519 KEM 스타일 캡슐화를 수행합니다.
    ///
    /// 1. 임시 키페어(ephemeral_sk, ephemeral_pk) 생성
    /// 2. 공유 비밀 = x25519_dh(ephemeral_sk, recipient_pk)
    /// 3. 반환: (공유 비밀, 임시 공개키를 암호문으로)
    ///
    /// @param keyPublic 수신자의 공개키
    /// @return 공유 비밀과 암호문(임시 공개키)을 포함하는 컨테이너
    @Override
    public SensitiveDataContainer encapsulate(@NotNull SensitiveDataContainer keyPublic)
            throws EntLibCryptoKEMProcessingException {
        if (keyPublic.getMemorySegment().byteSize() != _PK_SIZE)
            throw new EntLibCryptoKEMProcessingException(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );

        SensitiveDataContainer ephemeralSkContainer = new SensitiveDataContainer(_SK_SIZE);
        SensitiveDataContainer ephemeralPkContainer = new SensitiveDataContainer(_CT_SIZE);

        try {
            // ECDHE 에 마지막 E는 임시(Ephemeral)
            final ProgressResult ecdhePair = ProgressResult.fromCode((int) X25519StrategyBundle
                    .callNativeX25519Handle(0) // keygen type
                    .invokeExact(
                            ephemeralSkContainer.getMemorySegment(),
                            ephemeralPkContainer.getMemorySegment()
                    ));
            if (ecdhePair.isFail()) {
                ephemeralSkContainer.close();
                ephemeralPkContainer.close();
                throw new EntLibCryptoKEMProcessingException(
                        "ECDHE 키 페어 생성에 실패했습니다! 네이티브 코드 반환값: " + ecdhePair.getCode());
            }

            SensitiveDataContainer ssContainer = new SensitiveDataContainer(_SS_SIZE);
            SensitiveDataContainer ctContainer = ssContainer.addContainerData(_CT_SIZE);

            final ProgressResult dhResult = ProgressResult.fromCode((int) X25519StrategyBundle
                    .callNativeX25519Handle(2) // dh type
                    .invokeExact(
                            ssContainer.getMemorySegment(),
                            ephemeralSkContainer.getMemorySegment(),
                            keyPublic.getMemorySegment()
                    ));
            if (dhResult.isFail()) {
                ephemeralSkContainer.close();
                ephemeralPkContainer.close();
                ssContainer.close();
                throw new EntLibCryptoKEMProcessingException(
                        "DH 연산에 실패했습니다! 네이티브 코드 반환값: " + dhResult.getCode());
            }

            ctContainer.getMemorySegment().copyFrom(ephemeralPkContainer.getMemorySegment());

            ephemeralSkContainer.close();
            ephemeralPkContainer.close();

            return ssContainer;
        } catch (EntLibCryptoKEMProcessingException e) {
            throw e;
        } catch (Throwable e) {
            ephemeralSkContainer.close();
            ephemeralPkContainer.close();
            throw new EntLibNativeError("네이티브 에러", e);
        }
    }

    /// X25519 KEM 스타일 디캡슐화를 수행합니다.
    ///
    /// 공유 비밀 = x25519_dh(my_sk, ephemeral_pk)
    ///
    /// @param secretKeyContainer 자신의 비밀키
    /// @param ciphertext         상대방의 임시 공개키 (암호문)
    /// @return 복원된 공유 비밀
    @Override
    public SensitiveDataContainer decapsulate(@NotNull SensitiveDataContainer secretKeyContainer,
                                              @NotNull SensitiveDataContainer ciphertext)
            throws EntLibCryptoKEMProcessingException {
        if (secretKeyContainer.getMemorySegment().byteSize() != _SK_SIZE || ciphertext.getMemorySegment().byteSize() != _CT_SIZE)
            throw new EntLibSecurityError(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );

        SensitiveDataContainer ssContainer = new SensitiveDataContainer(_SS_SIZE);
        try {
            final ProgressResult result = ProgressResult.fromCode((int) X25519StrategyBundle
                    .callNativeX25519Handle(2) // dh type
                    .invokeExact(
                            ssContainer.getMemorySegment(),
                            secretKeyContainer.getMemorySegment(),
                            ciphertext.getMemorySegment()
                    ));
            if (result.isFail()) {
                ssContainer.close();
                throw new EntLibCryptoKEMProcessingException(
                        "키 디캡슐화(DH)에 실패했습니다! 네이티브 코드 반환값: " + result.getCode());
            }
        } catch (EntLibCryptoKEMProcessingException e) {
            throw e;
        } catch (Throwable e) {
            ssContainer.close();
            throw new EntLibNativeError("네이티브 에러", e);
        }
        return ssContainer;
    }

    /// X25519 Diffie-Hellman 공유 비밀을 계산합니다.
    ///
    /// 공유 비밀 = x25519_dh(my_sk, peer_pk)
    ///
    /// @param secretKeyContainer     자신의 비밀키
    /// @param peerPublicKeyContainer 상대방의 공개키
    /// @return 계산된 공유 비밀
    @Override
    public SensitiveDataContainer computeSharedSecret(SensitiveDataContainer secretKeyContainer,
                                                      SensitiveDataContainer peerPublicKeyContainer) {
        if (secretKeyContainer.getMemorySegment().byteSize() != _SK_SIZE || peerPublicKeyContainer.getMemorySegment().byteSize() != _PK_SIZE)
            throw new EntLibSecurityError(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );

        SensitiveDataContainer ssContainer = new SensitiveDataContainer(_SS_SIZE);
        try {
            final ProgressResult result = ProgressResult.fromCode((int) X25519StrategyBundle
                    .callNativeX25519Handle(2) // dh type
                    .invokeExact(
                            ssContainer.getMemorySegment(),
                            secretKeyContainer.getMemorySegment(),
                            peerPublicKeyContainer.getMemorySegment()
                    ));
            if (result.isFail()) {
                ssContainer.close();
                throw new EntLibSecurityError(
                        "공유 비밀 계산에 실패했습니다! 네이티브 코드 반환값: " + result.getCode());
            }
        } catch (Throwable e) {
            ssContainer.close();
            throw new EntLibNativeError("네이티브 에러", e);
        }
        return ssContainer;
    }

    @Override
    public String getAlgorithmName() {
        return "X25519";
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return type;
    }
}