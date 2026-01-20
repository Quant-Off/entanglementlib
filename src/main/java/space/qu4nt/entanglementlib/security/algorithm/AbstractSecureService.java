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

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.extern.slf4j.Slf4j;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
public abstract class AbstractSecureService extends SensitiveRegistry implements EntLibCryptoService {

    private boolean closed = false;

    /**
     * 서비스가 닫혔는지 확인하고, 닫혔다면 예외를 던지기 위한 메소드입니다.
     * 모든 {@code public} 메소드 시작 부분에서 호출해야 합니다.
     */
    protected void checkClosed() {
        if (closed) {
            throw new EntLibSecureIllegalStateException(EntLibCryptoService.class, "data-already-destroyed-exc",
                    this.getClass().getSimpleName());
        }
    }

    @Override
    public void close() {
        if (closed) return;

        destroyAll();

        closed = true;

        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-instance-closed", this.getClass().getSimpleName()));
    }

}
