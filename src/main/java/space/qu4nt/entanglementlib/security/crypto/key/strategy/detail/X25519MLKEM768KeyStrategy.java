/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoException;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.NativeEntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.hybrid.X25519MLKEM768Strategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.lang.foreign.MemorySegment;

/// X25519MLKEM768 하이브리드 알고리즘을 위한 키 페어 생성 전략 클래스입니다.
///
/// 이 알고리즘의 키 페어를 생성하기 위해 사전에 [X25519KeyStrategy]와
/// ML-KEM-768 알고리즘에 대한 [MLKEMKeyStrategy] 키 페어를 준비해야 합니다.
/// 이 클래스는 해당 객체를 전달받고 키 페어를 생성합니다.
///
/// 하이브리드 키 페어는 모두 `X25519` 값이 먼저 할당됩니다. 예를 들어, 공개 키의 경우
/// 다음의 수식으로 표현됩니다.
/// ```
/// HPK = XPK || MPK
/// ```
/// 여기서 XPK(X25519 공개 키)는 32바이트, MPK(ML-KEM-768 공개 키)는
/// 1184바이트입니다. 비밀 키도 동일한 방식으로 생성됩니다.
///
/// @author Q. T. Felix
/// @see EntLibAsymmetricKeyStrategy
/// @see X25519MLKEM768Strategy
/// @since 1.1.0
@Slf4j
public final class X25519MLKEM768KeyStrategy implements NativeEntLibAsymmetricKeyStrategy {

    @Setter
    @Nullable
    private X25519KeyStrategy x25519Key;
    @Setter
    @Nullable
    private MLKEMKeyStrategy mlkem768Key;

    private X25519MLKEM768KeyStrategy(final @Nullable X25519KeyStrategy x25519Key, final @Nullable MLKEMKeyStrategy mlkem768Key) {
        this.x25519Key = x25519Key;
        this.mlkem768Key = mlkem768Key;
    }

    public static X25519MLKEM768KeyStrategy create(final X25519KeyStrategy x25519Key, final MLKEMKeyStrategy mlkem768Key) {
        return new X25519MLKEM768KeyStrategy(x25519Key, mlkem768Key);
    }

    @Override
    public Pair<SensitiveDataContainer, SensitiveDataContainer> generateKeyPair() throws Throwable {
        if (x25519Key == null || mlkem768Key == null)
            throw new EntLibSecureIllegalStateException("X25519MLKEM768 알고리즘에 대한 키 생성을 수행할 수 없습니다! 이 작업을 수행하기 전에 X25519, ML-KEM-768 키 스트레티지를 생성해야 합니다.");
        // 하이브리드 페어 산출물
        final SensitiveDataContainer hPKContainer = new SensitiveDataContainer(KEMType.X25519MLKEM768.getParameterSizeDetail().getEncapsulationKeySize());
        final SensitiveDataContainer hSKContainer = new SensitiveDataContainer(KEMType.X25519MLKEM768.getParameterSizeDetail().getDecapsulationKeySize());

        // 중간 산출물
        Pair<SensitiveDataContainer, SensitiveDataContainer> xPair = null;
        Pair<SensitiveDataContainer, SensitiveDataContainer> mPair = null;
        try {
            // X25519
            xPair = x25519Key.generateKeyPair();
            SensitiveDataContainer xPk = xPair.getFirst();
            SensitiveDataContainer xSk = xPair.getSecond();

            // ML-KEM-768
            mPair = mlkem768Key.generateKeyPair();
            SensitiveDataContainer mPk = mPair.getFirst();
            SensitiveDataContainer mSk = mPair.getSecond();

            // 키 사이즈
            final int x25519KeySize = KEMType.X25519.getParameterSizeDetail().getEncapsulationKeySize();
            final int mlkem768PKSize = KEMType.ML_KEM_768.getParameterSizeDetail().getEncapsulationKeySize();
            final int mlkem768SKSize = KEMType.ML_KEM_768.getParameterSizeDetail().getDecapsulationKeySize();

            // 공개 키 결합
            MemorySegment.copy(xPk.getMemorySegment(), 0, hPKContainer.getMemorySegment(), 0, x25519KeySize);
            MemorySegment.copy(mPk.getMemorySegment(), 0, hPKContainer.getMemorySegment(), x25519KeySize, mlkem768PKSize);

            // 비밀 키 결합
            MemorySegment.copy(xSk.getMemorySegment(), 0, hSKContainer.getMemorySegment(), 0, x25519KeySize);
            MemorySegment.copy(mSk.getMemorySegment(), 0, hSKContainer.getMemorySegment(), x25519KeySize, mlkem768SKSize);

            return new Pair<>(hPKContainer, hSKContainer);
        } catch (Exception e) {
            hPKContainer.close();
            hSKContainer.close();
            throw new EntLibCryptoException(e);
        } finally {
            if (xPair != null) {
                xPair.getFirst().close();
                xPair.getSecond().close();
            }
            if (mPair != null) {
                mPair.getFirst().close();
                mPair.getSecond().close();
            }
        }
    }
}
