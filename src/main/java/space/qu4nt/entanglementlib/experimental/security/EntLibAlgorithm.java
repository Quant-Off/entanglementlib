/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

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
     * 키 생성 시 사용되는 알고리즘명과 암호화 수행에 사용되는 알고리즘명이
     * 상이한 경우 사용되는 Setter 메소드입니다.
     *
     * @param algorithm 수정할 알고리즘명
     * @return 전달받은 알고리즘명
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

    public AEADAdditional.AEADAdditionalBuilder aeadAdditional() {
        return AEADAdditional.builder();
    }

}
