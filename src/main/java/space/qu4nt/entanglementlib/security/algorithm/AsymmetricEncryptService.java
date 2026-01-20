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

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;

import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * {@link EntLibKeyPair} 객체를 사용하여 비대칭키 암호화 서비스를 정의하는 인터페이스입니다.
 * <p>
 * 이 인터페이스는 비대칭키 생성, 데이터 암호화(공개 키 사용) 및 복호화(비밀 키 사용)와 같은
 * 비대칭키 암호화 작업에 필요한 공통 기능을 제공합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public interface AsymmetricEncryptService extends EntLibCryptoService, KeyService {

    /**
     * 비대칭키 암호화에 사용되는 설정 정보를 담는 클래스입니다.
     * <p>
     * 암호화할 평문 데이터, 비대칭 키 타입, 패딩 방식 등의
     * 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    @Setter
    class Setting {
        private final byte[] plainByteArr;
        @Getter
        private ClassicalType type;
        @Getter
        private Mode mode;
        @Getter
        private Padding padding;
        @Getter
        private Digest digest;

        @lombok.Builder
        public Setting(String plain, byte[] plainByteArr, ClassicalType type, Padding padding) {
            if (plainByteArr != null) {
                this.plainByteArr = plainByteArr.clone(); // 방어적 복사
            } else if (plain != null) {
                this.plainByteArr = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(AsymmetricEncryptService.class, "plaintext-or-byte-array-exc");
            }
            this.padding = padding == null ? Padding.PKCS1 : padding;
        }

        public byte[] getPlainByteArr() {
            // 내부 배열 노출 방지를 위한 복사 반환
            return plainByteArr.clone();
        }
    }

    /**
     * 데이터를 암호화하는 메소드입니다.
     *
     * @param publicKey  암호화에 사용할 공개 키
     * @param plainBytes 암호화할 평문 데이터
     * @param padding    암호화에 사용할 패딩 방식
     * @param chunkSize  청크 크기 (0인 경우 청크 처리 안 함)
     * @return 암호화된 데이터 바이트 배열
     * @throws InvalidKeyException               잘못된 키가 제공된 경우
     * @throws NoSuchAlgorithmException          지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException           지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibSecureIllegalStateException 서비스가 이미 닫힌 경우
     */
    byte[] encrypt(@NotNull PublicKey publicKey, byte @NotNull [] plainBytes, @NotNull Padding padding, int chunkSize)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * 데이터를 복호화하는 메소드입니다.
     *
     * @param privateKey  복호화에 사용할 개인 키
     * @param cipherBytes 복호화할 암호문 데이터
     * @param padding     복호화에 사용할 패딩 방식
     * @param chunkSize   청크 크기 (0인 경우 청크 처리 안 함)
     * @return 복호화된 평문 데이터 바이트 배열
     * @throws InvalidKeyException               잘못된 키가 제공된 경우
     * @throws NoSuchAlgorithmException          지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException           지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibSecureIllegalStateException 서비스가 이미 닫힌 경우
     */
    byte[] decrypt(@NotNull PrivateKey privateKey, byte @NotNull [] cipherBytes, @NotNull Padding padding, int chunkSize)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;
}
