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

package space.qu4nt.entanglementlib.security;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.security.EntLibKeyDestroyException;

import javax.crypto.SecretKey;
import java.util.Objects;

/**
 * {@link SecretKey}를 래핑하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Slf4j
public class EntLibSecretKey implements EntLibKey<SecretKey> {

    private final SecretKey secretKey;
    /**
     * 이 값은 인코딩된 대칭키의 데이터를 절대 담지 않습니다.
     * <p>
     * {@link #EntLibSecretKey(SecretKey) 대칭키 객체를 통해 인스턴스가 생성된 경우}
     * 이 값은 반드시 {@code null}이어야 합니다.
     */
    private final byte[] secretBytes;

    private final boolean isByte;

    public EntLibSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
        this.secretBytes = null;
        this.isByte = false;
    }

    public EntLibSecretKey(byte[] secretBytes) {
        this.secretKey = null;
        this.secretBytes = secretBytes;
        this.isByte = true;
    }

    @Override
    public void wipe(@Nullable CustomWiper<@NotNull SecretKey> callback) {
        // NOTE: 아직 대안이 마련되지 않음
        //       KeyDestroyHelper#recursiveZeroing 메소드 참고
        try {
            if (secretKey != null) {
                KeyDestroyHelper.destroy(secretKey);
                if (callback != null)
                    callback.accept(secretKey);
            }
            if (secretBytes != null)
                KeyDestroyHelper.zeroing(secretBytes);
        } catch (Exception e) {
            throw new EntLibKeyDestroyException(e);
        }
    }

    public byte[] asBytes() {
        if (isByte)
            return secretBytes;
        return Objects.requireNonNull(secretKey).getEncoded();
    }
}
