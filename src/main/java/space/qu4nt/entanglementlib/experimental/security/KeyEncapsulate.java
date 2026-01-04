/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.security.builder.encapsulate.KeyEncapsulateSetting;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.util.Arrays;

/**
 * ML-KEM 키 캡슐화 및 디캡슐화를 지원하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Setter
@ApiStatus.Experimental
public final class KeyEncapsulate extends EntLibAlgorithm<EntLibKeyPair> {

    // FIPS 203 (타입을 KeyEncapsulate로 구체화하여 명시)
    public static final KeyEncapsulate ML_KEM_512 = new KeyEncapsulate("ML-KEM-512");
    public static final KeyEncapsulate ML_KEM_768 = new KeyEncapsulate("ML-KEM-768");
    public static final KeyEncapsulate ML_KEM_1024 = new KeyEncapsulate("ML-KEM-1024");

    private KeyEncapsulate(String rawAlgorithmName) {
        super(EntLibKeyPair.class, rawAlgorithmName, 0, false);
    }

    public KeyEncapsulateSetting.KeyEncapsulateSettingBuilder keyEncapsulateSetting() {
        return KeyEncapsulateSetting.builder();
    }

    /**
     * 공개 키를 사용하여 공유 비밀을 생성하고 캡슐화하는 메소드입니다.
     *
     * @param publicKeyOther 통신 상대방의 공개 키
     * @return 캡슐 (전자: 암호문, 후자: 공유비밀)
     */
    public static Pair<byte[], byte[]> encapsulate(final @NotNull AsymmetricKeyParameter publicKeyOther) {
        MLKEMGenerator generator = new MLKEMGenerator(InternalFactory.getSafeRandom());
        SecretWithEncapsulation secretWithEncapsulation = generator.generateEncapsulated(publicKeyOther);

        byte[] ciphertext = secretWithEncapsulation.getEncapsulation();
        byte[] sharedSecretMLKEM = secretWithEncapsulation.getSecret();

        // 안전한 반환을 위해 복사본 생성
        final Pair<byte[], byte[]> result = new Pair<>(
                Arrays.copyOf(ciphertext, ciphertext.length),
                Arrays.copyOf(sharedSecretMLKEM, sharedSecretMLKEM.length)
        );

        // Zeroing
        KeyDestroyHelper.zeroing(ciphertext);
        KeyDestroyHelper.zeroing(sharedSecretMLKEM);

        return result;
    }

    /**
     * 개인 키를 사용하여 캡슐을 해제하고 공유 비밀을 추출합니다.
     * <p>
     * <strong>주의:</strong> 반환된 바이트 배열은 사용 후 반드시 소거(Zeroing)해야 합니다.
     *
     * @param privateKeyMine 자신의 개인 키 (MLKEMPrivateKeyParameters)
     * @param encapsulation  상대방으로부터 수신한 캡슐 (Ciphertext)
     * @return 추출된 공유 비밀 (Shared Secret)
     */
    public static EntLibSecretKey decapsulate(final @NotNull MLKEMPrivateKeyParameters privateKeyMine,
                                              final byte @NotNull [] encapsulation) {
        if (!(privateKeyMine instanceof MLKEMPrivateKeyParameters)) {
            throw new IllegalArgumentException("Key must be an instance of MLKEMPrivateKeyParameters");
        }

        MLKEMExtractor extractor = new MLKEMExtractor(privateKeyMine);
        byte[] sharedSecret = extractor.extractSecret(encapsulation);

        // 추출된 비밀의 복사본을 반환 (원본은 BC 내부에서 처리되거나 GC 대상)
        // 안전성을 위해 호출자가 반환값을 관리하도록 함
        return new EntLibSecretKey(Arrays.copyOf(sharedSecret, sharedSecret.length));
    }
}