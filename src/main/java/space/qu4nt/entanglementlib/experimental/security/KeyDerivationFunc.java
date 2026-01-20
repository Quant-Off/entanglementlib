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

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;
import space.qu4nt.entanglementlib.experimental.security.builder.derivesetting.KeyDerivationSetting;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.util.Nill;

import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * 키 유도 함수
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Setter
@SuppressWarnings("rawtypes")
@ApiStatus.Experimental
public final class KeyDerivationFunc extends EntLibAlgorithm {

    public static final KeyDerivationFunc HKDF_SHA256 = new KeyDerivationFunc("HKDF-SHA256");
    public static final KeyDerivationFunc HKDF_SHA384 = new KeyDerivationFunc("HKDF-SHA384");
    public static final KeyDerivationFunc HKDF_SHA512 = new KeyDerivationFunc("HKDF-SHA512");

    // NOTE: PBKDF2는 불안정한 패스워드 기반이기 떄문에 현재로썬 추가 의향 X

    private String kdfAlgorithmName;

    private KeyDerivationFunc(String kdfAlgorithmName) {
        //noinspection unchecked
        super(null, null, 0, false);
        this.kdfAlgorithmName = kdfAlgorithmName;
    }

    public KeyDerivationSetting.KeyDerivationSettingBuilder keyDerivationSetting() {
        return KeyDerivationSetting.builder();
    }

    @Override
    public EntLibKey<?> keyGen() {
        throw new RuntimeException("cant keygen");
    }

    /**
     * 키 유도, 기본적으로 jca 사용
     * <p>
     * 주의: 송/수신간에 salt 값이 다를 경우 유도 불가능합니다.
     *
     * @param kdf
     * @param keyDerivationSetting
     * @param salt
     * @param information
     * @param outputLength
     * @param initKeyMaterials     유도에 포함할 대칭키 배열
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static EntLibSecretKey derive(KeyDerivationFunc kdf,
                                         @NotNull KeyDerivationSetting keyDerivationSetting,
                                         final byte @Nullable @Range(from = 32, to = 64) [] salt,
                                         final byte @Nullable [] information,
                                         int outputLength,
                                         EntLibSecretKey... initKeyMaterials)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final AlgorithmParameter deriveAlgorithm = Nill.nullDef(keyDerivationSetting.getKeyDeriveAlgorithm(), () -> AlgorithmParameter.AES);
        String kdfAlgorithmName = kdf.getKdfAlgorithmName();
        KDF kdfInstance = KDF.getInstance(kdfAlgorithmName);

        final byte[] saltFix;
        if (salt == null) {
            // RFC 5869: Salt가 없으면 HashLen 만큼의 0으로 채워진 바이트 문자열로 설정
            int hashLen = kdfAlgorithmName.contains("256") ? 32 :
                    kdfAlgorithmName.contains("384") ? 48 :
                            kdfAlgorithmName.contains("512") ? 64 : 32;
            saltFix = new byte[hashLen]; // 자바 배열은 기본값이 0
        } else {
            saltFix = salt;
        }

        final AlgorithmParameterSpec algParams = HKDFParameterSpec.ofExtract()
                .addIKM(combineKeys(initKeyMaterials))
                .addSalt(saltFix)
                .thenExpand(information, outputLength < 31 ? 32 : outputLength);

        return new EntLibSecretKey(kdfInstance.deriveKey(deriveAlgorithm.getName(), algParams));
    }
    // TODO: 사용자가 가변 인자를 전달하지 않고 이미 조합된 단일 인자를 전달할 수 있는 메소드 추가 예정

    public static byte[] combineKeys(EntLibSecretKey... keys) {
        if (keys == null || keys.length == 0) {
            throw new IllegalArgumentException("At least one key material is required.");
        }

        // 총 길이 계산
        int totalLen = 0;
        for (EntLibSecretKey key : keys) {
            totalLen += key.asBytes().length;
        }

        // 버퍼 할당
        byte[] combined = new byte[totalLen];

        // 복사
        int offset = 0;
        for (EntLibSecretKey key : keys) {
            byte[] keyBytes = key.asBytes(); // 내부 키 바이트 접근
            System.arraycopy(keyBytes, 0, combined, offset, keyBytes.length);
            offset += keyBytes.length;
        }

        return combined;
    }
}
