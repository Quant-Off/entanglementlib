/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 대칭키 암호화 서비스를 정의하는 인터페이스입니다.
 * <p>
 * 이 인터페이스는 대칭키 생성, 데이터 암호화 및 복호화와 같은
 * 대칭키 암호화 작업에 필요한 공통 기능을 제공합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public interface SymmetricCryptoService extends EntLibCryptoService, KeyService {

    /**
     * 대칭키 암호화에 사용되는 설정 정보를 담는 클래스입니다.
     * <p>
     * 암호화할 평문 데이터, 대칭 키 타입, 패딩 방식, 청크 크기 등의
     * 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    class Setting {
        private final byte[] plainByteArr;
        @Getter
        private final ClassicalType type;
        @Getter
        private final Padding padding;
        @Getter
        private final int chunkSize;

        @lombok.Builder
        public Setting(String plain, byte[] plainByteArr, ClassicalType type, Padding padding, int chunkSize) {
            if (plainByteArr != null) {
                this.plainByteArr = plainByteArr.clone(); // 방어적 복사
            } else if (plain != null) {
                this.plainByteArr = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(SymmetricCryptoService.class, "plaintext-or-byte-array-exc");
            }
            this.type = (type == null || !type.getMethod().equals(CryptoMethod.SYMMETRIC)) ? ClassicalType.AES256 : type;
            this.padding = padding == null ? Padding.PKCS5 : padding;
            this.chunkSize = chunkSize;
        }

        public byte[] getPlainByteArr() {
            // 내부 배열 노출 방지를 위한 복사 반환
            return plainByteArr.clone();
        }
    }

    /**
     * 데이터를 암호화하는 메소드입니다.
     *
     * @param secretKey  암호화에 사용할 대칭 키
     * @param plainBytes 암호화할 평문 데이터
     * @param padding    암호화에 사용할 패딩 방식
     * @param chunkSize  청크 크기 (0인 경우 청크 처리 안 함)
     * @return 암호화된 데이터 바이트 배열
     * @throws InvalidKeyException               잘못된 키가 제공된 경우
     * @throws NoSuchAlgorithmException          지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException           지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibSecureIllegalStateException 서비스가 이미 닫힌 경우
     */
    byte[] encrypt(@NotNull SecretKey secretKey, byte @NotNull [] plainBytes, @NotNull Padding padding, int chunkSize)
            throws Exception;

    /**
     * 데이터를 복호화하는 메소드입니다.
     *
     * @param secretKey   복호화에 사용할 대칭 키
     * @param cipherBytes 복호화할 암호문 데이터
     * @param padding     복호화에 사용할 패딩 방식
     * @param chunkSize   청크 크기 (0인 경우 청크 처리 안 함)
     * @return 복호화된 평문 데이터 바이트 배열
     * @throws InvalidKeyException               잘못된 키가 제공된 경우
     * @throws NoSuchAlgorithmException          지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException           지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibSecureIllegalStateException 서비스가 이미 닫힌 경우
     */
    byte[] decrypt(@NotNull SecretKey secretKey, byte @NotNull [] cipherBytes, @NotNull Padding padding, int chunkSize)
            throws Exception;
}
