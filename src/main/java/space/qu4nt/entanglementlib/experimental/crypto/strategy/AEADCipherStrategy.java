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

package space.qu4nt.entanglementlib.experimental.crypto.strategy;

/// AEAD(Authenticated Encryption with Associated Data)를 지원하는 암호화 전략 인터페이스입니다.
///
/// GCM, CCM 등의 AEAD 모드에서 AAD(Additional Authenticated Data)를 설정할 수 있는 기능을 제공합니다.
/// ChaCha20-Poly1305와 같은 AEAD 알고리즘도 이 인터페이스를 구현합니다.
///
/// @author Q. T. Felix
/// @see CipherStrategy
/// @since 1.1.0
public interface AEADCipherStrategy extends CipherStrategy {

    /**
     * AAD(Additional Authenticated Data)를 설정하는 메소드입니다.
     * <p>
     * AAD는 암호화되지 않지만 무결성이 보장됩니다.
     * 암호화/복호화 수행 전에 호출되어야 합니다.
     *
     * @param aad 추가 인증 데이터
     * @return 메소드 체이닝을 위한 {@code this}
     */
    AEADCipherStrategy updateAAD(byte[] aad);

}
