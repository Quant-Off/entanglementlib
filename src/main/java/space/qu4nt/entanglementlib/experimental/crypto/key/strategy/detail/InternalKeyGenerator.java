/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import space.qu4nt.entanglementlib.InternalFactory;

/**
 * 내부적으로 사용되는 암호화 키 생성기 유틸리티 클래스입니다.
 * <p>
 * {@link CipherKeyGenerator}를 초기화하여 지정된 크기의 안전한 난수 키를 생성합니다.
 * 이 클래스는 패키지 내부에서만 사용되며 외부에 노출되지 않습니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
final class InternalKeyGenerator {

    /**
     * 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private InternalKeyGenerator() {}

    /**
     * 지정된 키 크기로 초기화된 {@link CipherKeyGenerator}를 반환하는 메소드입니다.
     * <p>
     * 안전한 난수 생성기({@link space.qu4nt.entanglementlib.InternalFactory#getSafeRandom()})를
     * 사용하여 키 생성기를 초기화합니다.
     * </p>
     *
     * @param keySize 생성할 키의 비트 크기
     * @return 초기화된 {@link CipherKeyGenerator}
     */
    static CipherKeyGenerator initializedCipherKeyGenerator(final int keySize) {
        final CipherKeyGenerator keyGenerator = new CipherKeyGenerator();
        keyGenerator.init(new KeyGenerationParameters(InternalFactory.getSafeRandom(), keySize));
        return keyGenerator;
    }
}
