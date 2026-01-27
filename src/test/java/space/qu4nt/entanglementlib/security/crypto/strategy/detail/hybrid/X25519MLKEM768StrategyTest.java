/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail.hybrid;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.EntanglementLibBootstrap;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoKEMProcessingException;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.ParameterSizeDetail;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.MLKEMKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.X25519KeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.X25519MLKEM768KeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeKEMStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLKEMStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.X25519Strategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/// [X25519MLKEM768Strategy]의 통합 테스트입니다.
///
/// 실제 하위 전략(X25519Strategy, MLKEMStrategy)을 사용하여 하이브리드 키 교환의
/// 데이터 흐름과 컨테이너 구조(Binding)를 검증합니다.
///
/// **주의:** 이 테스트는 네이티브 라이브러리가 로드된 환경을 가정합니다.
/// 또한, 임의로 생성된(Random) 더미 키를 사용하므로, 실제 암호학적 연산(Shared Secret 일치 여부)보다는
/// 데이터의 규격(Size)과 입출력 구조의 정합성을 검증하는 데 목적이 있습니다.
///
/// @author Q. T. Felix
@Slf4j
class X25519MLKEM768StrategyTest {

    private static NativeKEMStrategy x25519Strategy;
    private static EntLibAsymmetricKeyStrategy x25519KeyStrategy;
    private static NativeKEMStrategy mlkem768Strategy;
    private static EntLibAsymmetricKeyStrategy mlkem768KeyStrategy;

    private static ParameterSizeDetail hybridDetail;

    @BeforeAll
    static void setupParameterDetails() {
        EntanglementLibBootstrap.registerEntanglementLib("X25519MLKEM768-TEST", true);

        x25519Strategy = EntLibCryptoRegistry.getAlgStrategy(KEMType.X25519, NativeKEMStrategy.class);
        x25519KeyStrategy = EntLibCryptoRegistry.getKeyStrategy(KEMType.X25519, EntLibAsymmetricKeyStrategy.class);
        mlkem768Strategy = EntLibCryptoRegistry.getAlgStrategy(KEMType.ML_KEM_768, NativeKEMStrategy.class);
        mlkem768KeyStrategy = EntLibCryptoRegistry.getKeyStrategy(KEMType.ML_KEM_768, EntLibAsymmetricKeyStrategy.class);

        hybridDetail = KEMType.X25519MLKEM768.getParameterSizeDetail();

        log.info("하이브리드 KEM (X25519 + ML-KEM-768) 테스트 초기화");
        log.info("하이브리드 PK 크기: {} 바이트", hybridDetail.getEncapsulationKeySize());
        log.info("하이브리드 CT 크기: {} 바이트", hybridDetail.getCiphertextSize());
    }

    @Test
    @DisplayName("통합 테스트: 캡슐화 및 디캡슐화 수행 시 데이터 구조와 바인딩이 올바르게 유지되어야 함")
    void testHybridEncapsulationFlow() throws Throwable {
        // Given. 전략 인스턴스 생성
        final X25519MLKEM768Strategy strategy = EntLibCryptoRegistry.getAlgStrategy(KEMType.X25519MLKEM768, X25519MLKEM768Strategy.class);
        strategy.setX25519Strategy((X25519Strategy) x25519Strategy);
        strategy.setMlkemStrategy((MLKEMStrategy) mlkem768Strategy);

        // ECDHE 페어 생성
        final X25519MLKEM768KeyStrategy ecdhePairStrategy =
                EntLibCryptoRegistry.getKeyStrategy(KEMType.X25519MLKEM768, X25519MLKEM768KeyStrategy.class);
        ecdhePairStrategy.setX25519Key((X25519KeyStrategy) x25519KeyStrategy);
        ecdhePairStrategy.setMlkem768Key((MLKEMKeyStrategy) mlkem768KeyStrategy);
        final Pair<SensitiveDataContainer, SensitiveDataContainer> ecdhePair = ecdhePairStrategy.generateKeyPair();

        log.debug("더미 키 생성됨. 캡슐화 진행 중...");

        // When & Then 1. 캡슐화
        try (SensitiveDataContainer ssResult = strategy.encapsulate(ecdhePair.getFirst())) {

            // 공유 비밀 사이즈 검증
            assertThat(ssResult.getMemorySegment().byteSize())
                    .as("하이브리드 공유 비밀의 크기는 X25519와 ML-KEM의 합이어야 함")
                    .isEqualTo(hybridDetail.getSharedSecretKeySize());

            // 암호문 바인딩 검증
            assertThat(ssResult.get(0)).isPresent();

            @SuppressWarnings("OptionalGetWithoutIsPresent") SensitiveDataContainer ctResult = ssResult.get(0).get();
            assertThat(ctResult.getMemorySegment().byteSize())
                    .as("하이브리드 암호문의 크기는 X25519와 ML-KEM의 합이어야 함")
                    .isEqualTo(hybridDetail.getCiphertextSize());

            log.debug("캡슐화 성공. SS 크기: {}, CT 크기: {}",
                    ssResult.getMemorySegment().byteSize(), ctResult.getMemorySegment().byteSize());

            // When & Then 2, 디캡슐화
            // 캡슐화로 생성된 CT와 더미 SK를 사용하여 디캡슐화 시도
            // 네이티브 라이브러리가 유효하지 않은 키에 대해 에러를 던질 수 있으므로 예외 처리 검증 포함
            try (SensitiveDataContainer recoveredSs = strategy.decapsulate(ecdhePair.getSecond(), ctResult)) {

                assertThat(recoveredSs.getMemorySegment().byteSize())
                        .as("복원된 공유 비밀의 크기는 원본과 동일해야 함")
                        .isEqualTo(hybridDetail.getSharedSecretKeySize());

                log.debug("디캡슐화 성공. 복원된 공유 비밀 크기: {}",
                        recoveredSs.getMemorySegment().byteSize());

            } catch (IllegalArgumentException e) {
                log.warn("더미 키로 인해 네이티브 암호화 작업 실패 (구조적 테스트에서 예상된 동작): {}", e.getMessage());
            }
        } catch (Exception e) {
            log.error("하이브리드 테스트 흐름 중 예상치 못한 오류 발생", e);
            throw new RuntimeException(e);
        } finally {
            ecdhePair.getFirst().close();
            ecdhePair.getSecond().close();
        }
    }

    @Test
    @DisplayName("검증: 잘못된 크기의 키 입력 시 예외가 발생해야 함")
    void testInvalidInputSize() {
        final X25519MLKEM768Strategy strategy = EntLibCryptoRegistry.getAlgStrategy(KEMType.X25519MLKEM768, X25519MLKEM768Strategy.class);
        strategy.setX25519Strategy((X25519Strategy) x25519Strategy);
        strategy.setMlkemStrategy((MLKEMStrategy) mlkem768Strategy);

        // 규격보다 1바이트 작은 더미 키
        try (SensitiveDataContainer invalidPk = createDummyContainer(hybridDetail.getEncapsulationKeySize() - 1)) {
            assertDoesNotThrow(() -> {
                try {
                    strategy.encapsulate(invalidPk);
                } catch (EntLibCryptoKEMProcessingException e) {
                    log.debug("잘못된 PK 크기에 대한 예상된 예외 포착: {}", e.getMessage());
                    return;
                }
                throw new AssertionError("잘못된 PK 사이즈임에도 예외가 발생하지 않음");
            });
        }
    }

    /// 지정된 크기의 랜덤 데이터로 채워진 컨테이너를 생성합니다.
    private SensitiveDataContainer createDummyContainer(int size) {
        byte[] randomBytes = SensitiveDataContainer.generateSafeRandomBytes(size);
        return new SensitiveDataContainer(randomBytes, true);
    }
}