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

package space.qu4nt.entanglementlib.experimental.security.builder.blockcipher;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.algorithm.Digest;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;

import java.util.Arrays;
import java.util.Objects;

/**
 * 블록 암호화 설정을 위한 빌더 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@ApiStatus.Experimental
public final class BlockCipherSetting {

    private final String algorithm;
    private final Mode mode;
    private final Padding padding;
    private final Digest digest;
    private final byte[] iv;

    private final String fullModeName;

    public static BlockCipherSettingBuilder builder() {
        return new BlockCipherSettingBuilder();
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class BlockCipherSettingBuilder {
        private String algorithm;
        private Mode mode;
        private Padding padding;
        private Digest digest;
        private byte[] iv;

        public BlockCipherSettingBuilder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public BlockCipherSettingBuilder mode(Mode mode) {
            this.mode = mode;
            return this;
        }

        public BlockCipherSettingBuilder padding(Padding padding) {
            this.padding = padding;
            return this;
        }

        public BlockCipherSettingBuilder digest(Digest digest) {
            this.digest = digest;
            return this;
        }

        public BlockCipherSettingBuilder iv(byte[] iv) {
            this.iv = Arrays.copyOf(iv, iv.length);
            KeyDestroyHelper.zeroing(iv);
            return this;
        }

        public BlockCipherSetting done() {
            return new BlockCipherSetting(algorithm, mode, padding, digest, iv,
                    Mode.getFullName(algorithm,
                            Objects.requireNonNull(mode),
                            Objects.requireNonNull(padding),
                            digest));
        }

    }
}
