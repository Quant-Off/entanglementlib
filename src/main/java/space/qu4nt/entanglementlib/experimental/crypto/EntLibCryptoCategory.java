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

package space.qu4nt.entanglementlib.experimental.crypto;

/// 암호화 알고리즘의 유형을 분류하는 열거형 클래스입니다.
///
/// 이 클래스는 `BouncyCastle Lightweight API` 환경에서 사용되는 다양한 암호화 서비스 중,
/// 실질적인 암호화 연산, 서명, 키 합의 등을 수행하는 핵심 알고리즘 카테고리를 정의합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
public enum EntLibCryptoCategory {

    /**
     * 데이터의 기밀성을 보장하기 위한 암호화 및 복호화 알고리즘 카테고리입니다.
     * <p>
     * 대칭 키 암호(block cipher, stream cipher) 및 비대칭 키 암호 알고리즘이 포함됩니다.
     */
    CIPHER,

    /**
     * 데이터의 무결성과 인증을 보장하기 위한 전자 서명 알고리즘 카테고리입니다.
     * <p>
     * 메시지 서명 및 검증을 수행하는 알고리즘들이 포함됩니다.
     */
    SIGNATURE,

    /**
     * 두 당사자 간에 비밀 키를 공유하기 위한 키 합의 프로토콜 카테고리입니다.
     * <p>
     * 안전하지 않은 채널을 통해 공통의 비밀 키를 생성하는 알고리즘들이 포함됩니다.
     */
    KEY_AGREEMENT,

    /**
     * 메시지의 무결성과 인증을 확인하기 위한 메시지 인증 코드(MAC) 알고리즘 카테고리입니다.
     * <p>
     * 비밀 키를 사용하여 메시지의 위변조 여부를 확인하는 알고리즘들이 포함됩니다.
     */
    MAC,

    /**
     * 임의의 길이의 데이터를 고정된 길이의 해시 값으로 변환하는 메시지 다이제스트 알고리즘 카테고리입니다.
     * <p>
     * 데이터의 고유한 지문(fingerprint)을 생성하는 알고리즘들이 포함됩니다.
     */
    MESSAGE_DIGEST,

    /**
     * 키 캡슐화 메커니즘(Key Encapsulation Mechanism, KEM) 알고리즘 카테고리입니다.
     * <p>
     * 공개 키 암호화를 사용하여 대칭 키를 안전하게 전송하기 위한 기법으로,
     * 포스트 퀀텀 암호화(PQC) 등에서 주로 사용됩니다.
     */
    KEM,

}
