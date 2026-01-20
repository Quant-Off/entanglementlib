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
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.security.builder.AEADAdditional;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * 알고리즘을 중앙에서 손쉽게 제어하기 위한 클래스입니다.
 * 외부에서 인스턴스를 생성할 수 없습니다.
 * <p>
 * 스케치:
 * <pre>{@code
 * // AES 알고리즘의 경우
 * // 키 생성
 * EntLibAlgorithm.AES256   // Return: EntLibAlgorithm.BlockCipher<EntLibSecretKey>
 *     .keyGen("Provider"); // Return: EntLibSecretKey (implements EntLibKey<SecretKey>)
 *
 * // 블록 암호화 관련 설정
 * EntLibAlgorithm.AES256
 *     .blockCipherSetting() // Return: EntLibBlockCipherSetting.EntLibBlockCipherSettingBuilder
 *     .mode(...)
 *     .padding(...)
 *     .digest(...)
 *     .done()               // Return: EntLibBlockCipherSettingResult
 * }</pre>
 * <p>
 * 교착 상태 방지를 위해 알고리즘은 나눠짐
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@ApiStatus.Experimental
public class EntLibAlgorithm<KT extends EntLibKey<?>> {

    private final Class<KT> keyType;
    private String keyGenerateAlgorithm;
    private final int keySize;
    private final boolean canAEAD;

    protected EntLibAlgorithm(Class<KT> keyType, String keyGenerateAlgorithm, int keySize, boolean canAEAD) {
        this.keyType = keyType;
        this.keyGenerateAlgorithm = keyGenerateAlgorithm;
        this.keySize = keySize;
        this.canAEAD = canAEAD;
    }

    /**
     * 키 생성 시 사용되는 알고리즘명을 변경하는 메소드입니다.
     * <p>
     * 이 메소드는 사용하고자 하는 알고리즘의 키 서비스를 정밀하게
     * 조정하고자 할 때 사용됩니다.
     *
     * @param algorithm 수정할 알고리즘명
     * @return 빌더 패턴
     */
    public EntLibAlgorithm<KT> changeKeyGenerateAlgorithm(@NotNull String algorithm) {
        this.keyGenerateAlgorithm = algorithm;
        return this;
    }

    @SuppressWarnings("unchecked")
    public KT keyGen(@Nullable String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (keyType.equals(EntLibKeyPair.class))
            return (KT) InternalFactory.Key.keyPairGen(keyGenerateAlgorithm, keySize, provider);
        return (KT) InternalFactory.Key.secretKeygen(keyGenerateAlgorithm, keySize, provider);
    }

    public KT keyGen() throws NoSuchAlgorithmException, NoSuchProviderException {
        return keyGen(null);
    }

    public AEADAdditional aeadAdditional(final byte @NotNull [] aad) {
        byte[] r = Arrays.copyOf(aad, aad.length);
        KeyDestroyHelper.zeroing(aad);
        return new AEADAdditional(r);
    }

}
