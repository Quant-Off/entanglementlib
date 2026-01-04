/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder.blockcipher;

import lombok.Builder;
import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.experimental.security.EntLibAlgorithm;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.algorithm.Digest;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;

import java.util.Objects;

/**
 * 블록 암호화 설정을 위한 빌더 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@ApiStatus.Experimental
public final class BlockCipherSetting {

    private final EntLibAlgorithm<? extends EntLibKey<?>> algorithm;
    private final Mode mode;
    private final Padding padding;
    private final Digest digest;
    private final byte[] iv;

    @Builder
    public BlockCipherSetting(EntLibAlgorithm<? extends EntLibKey<?>> algorithm, Mode mode, Padding padding, Digest digest, byte[] iv) {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        this.digest = digest;
        this.iv = iv.clone();
    }

    public BlockCipherSettingResult done() {
        return new BlockCipherSettingResult(mode, padding, digest,
                Mode.getFullName(algorithm.getKeyGenerateAlgorithm(),
                        Objects.requireNonNull(mode),
                        Objects.requireNonNull(padding),
                        digest), iv);
    }

    public static class BlockCipherSettingBuilder {
        public BlockCipherSettingResult done() {
            return build().done();
        }
    }
}
