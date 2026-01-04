/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.EntanglementLibBootstrap;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.security.builder.blockcipher.BlockCipherSettingResult;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;
import space.qu4nt.entanglementlib.util.wrapper.Hex;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

/**
 * TLSv1.3 {@code X25519MLKEM768} 프로토콜 통신 가정 테스트
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
class HybridKeyExchangeTest {

    @Test
    @DisplayName("X25519MLKEM768")
    void x25519mlkem768Test() throws Exception {
        EntanglementLibBootstrap.registerEntanglementLib("X25519MLKEM768 Test", true);
        // Alice - 클라이언트, Bob - 서버

        // 1. bob 키 생성
        log.info("1. bob 키 생성");
        HybridKeyExchange bobX25519mlkem768 = HybridKeyExchange.X25519_MLKEM_768;
        EntLibKeyPair bobXPair = bobX25519mlkem768.getKeyExchangeDetail().keyGen(InternalFactory.getBCNormalProvider());
        EntLibKeyPair bobKemPair = bobX25519mlkem768.getKemDetail().keyGen(InternalFactory.getBCNormalProvider());

        // 2. alice에게 bob공개키 전달됨

        // 3. alice ecdhe 키 페어 생성
        log.info("2. alice에게 bob 공개키 모두 전달, 3. alice ecdhe 키 페어 생성");
        KeyExchange aliceECDHE = KeyExchange.X25519;
        EntLibKeyPair aliceXEPair = aliceECDHE.keyGen(InternalFactory.getBCNormalProvider());

        // 4. alice는 bob의 x25519 공개키와 자신의 ecdhe 비밀키로 키 합의 -> 공유 비밀 1
        log.info("4. alice는 bob의 x25519 공개키와 자신의 ecdhe 비밀키로 키 합의 -> 공유 비밀 1");
        final EntLibSecretKey sharedSecret1 = KeyExchange.genAgreementSecret(aliceECDHE, InternalFactory.getBCNormalProvider(), aliceXEPair, bobXPair.keyPair().getPublic());

        // 5. alice는 bob의 kem 공개키로 캡슐화 -> 캡슐(암호문, 공유 비밀 2)
        log.info("5. alice는 bob의 kem 공개키로 캡슐화 -> 캡슐(암호문, 공유 비밀 2)");
        BCMLKEMPublicKey bcMLKEMPublicKey = (BCMLKEMPublicKey) bobKemPair.keyPair().getPublic();
        byte[] pkdata = bcMLKEMPublicKey.getPublicData();
        MLKEMParameters pkparams = MLKEMParameters.ml_kem_768;
        MLKEMPublicKeyParameters r = new MLKEMPublicKeyParameters(pkparams, pkdata);
        Pair<byte[], byte[]> kemCapsule = KeyEncapsulate.encapsulate(r);
        final byte[] ciphertextInCapsule = kemCapsule.getFirst();
        final EntLibSecretKey sharedSecret2 = new EntLibSecretKey(kemCapsule.getSecond()); // 바이트배열

        log.info("alice측 공유 비밀 1,2: {}, {}", Hex.toHexString(sharedSecret1.asBytes()), Hex.toHexString(sharedSecret2.asBytes()));

        // 5-1. alice, bob 둘 다 사용할 salt와 평문 암/복호화에 사용될 iv, KDF에 사용될 information 바이트 배열 선언
        log.info("5-1. alice, bob 둘 다 사용할 salt와 평문 암/복호화에 사용될 iv, KDF에 사용될 information 바이트 배열 선언");
        byte @NotNull [] commonSalt = EntLibKey.generateSafeRandomBytes(32);
        byte @NotNull [] commonIv = EntLibKey.generateSafeRandomBytes(16);
        byte @NotNull [] commonInfo = "X25519-ML-KEM-768-using-HKDF-SHA256".getBytes(StandardCharsets.UTF_8);

        // 6. alice는 공유비밀 1, 2를 사용해 키 유도 -> 최종 대칭키
        log.info("6. alice는 공유비밀 1, 2를 사용해 키 유도 -> 최종 대칭키");
        KeyDerivationFunc aliceKDFunc = KeyDerivationFunc.HKDF_SHA256; // 사용할 키 유도 함수(bob도 동일)
        final EntLibSecretKey symmetricKeyFinal = KeyDerivationFunc.derive(
                aliceKDFunc,
                aliceKDFunc.keyDerivationSetting().keyDeriveAlgorithm(AlgorithmParameter.AES).done(),
                commonSalt,
                commonInfo,
                32,
                sharedSecret1, sharedSecret2
        );
        log.info("alice측 최종 대칭키 hex: {}", Hex.toHexString(symmetricKeyFinal.asBytes()));

        // 7. alice는 최종 대칭키로 평문 암호화 후 암호화된 평문과 ECDHE 공개키, 캡슐에 든 암호문 전송
        log.info("7. alice는 최종 대칭키로 평문 암호화 후 암호화된 평문과 ECDHE 공개키, 캡슐에 든 암호문 전송");
        String plain = "This is Hybrid Quantum World!!!!!";
        byte[] plainBytes = plain.getBytes(StandardCharsets.UTF_8);
        BlockCipher aesPlainEnc = BlockCipher.AES256;
        BlockCipherSettingResult aesSettingResult = aesPlainEnc.blockCipherSetting()
                .mode(Mode.CBC)
                .padding(Padding.PKCS5)
                .iv(commonIv)
                .done();
        byte[] encryptedPlain = BlockCipher.blockCipherEncrypt(
                null,
                plainBytes,
                symmetricKeyFinal, // aes 키 생성 필요 X, 최종 대칭키로 암호화 O
                aesSettingResult,
                null,
                0,
                null
        );
        // 다음 세 개 전달
        // encryptedPlain
        // ciphertextInCapsule
        // alice ecdhe 공개키(aliceXEPair.getPublic)

        // 8. bob이 받음
        log.info("8. bob이 받음");

        // bob은 받은 3개의 데이터를 자신의 개인 키들로 복호화
        // 9. alice의 ecdhe 공개키와 bob의 ecdh 비밀키로 공유 비밀 1 복호화
        log.info("9. alice의 ecdhe 공개키와 bob의 ecdh 비밀키로 공유 비밀 1 복호화");
        PublicKey aliceECDHEPk = aliceXEPair.keyPair().getPublic();
        final EntLibSecretKey bobReceivedSharedSecret1 = KeyExchange.genAgreementSecret(
                bobX25519mlkem768.getKeyExchangeDetail(),
                InternalFactory.getBCNormalProvider(),
                bobXPair,
                aliceECDHEPk);

        // 10. bob의 mlkem768 비밀키로 암호문 디캡슐화 (ciphertextInCapsule 사용) -> 공유 비밀 2 얻음
        log.info("10. bob의 mlkem768 비밀키로 암호문 디캡슐화 (ciphertextInCapsule 사용) -> 공유 비밀 2 얻음");
        BCMLKEMPrivateKey bcMLKEMPrivateKeybob = (BCMLKEMPrivateKey) bobKemPair.keyPair().getPrivate();
        byte[] skdatabob = bcMLKEMPrivateKeybob.getPrivateData();
        MLKEMParameters skparamsbob = MLKEMParameters.ml_kem_768;
        MLKEMPrivateKeyParameters rbob = new MLKEMPrivateKeyParameters(skparamsbob, skdatabob);
        final EntLibSecretKey bobReceivedSharedSecret2 = KeyEncapsulate.decapsulate( // 내부적으로 바이트배열
                rbob,
                ciphertextInCapsule);
        log.info("bob측 공유 비밀 1,2: {}, {}", Hex.toHexString(bobReceivedSharedSecret1.asBytes()), Hex.toHexString(bobReceivedSharedSecret2.asBytes()));

        // 11. bob도 키 유도 수행 -> 최종 대칭키 얻음
        log.info("11. bob도 키 유도 수행 -> 최종 대칭키 얻음");
        final EntLibSecretKey bobKDFSymmetricKeyFinal = KeyDerivationFunc.derive(
                aliceKDFunc, // alice와 동일한 KDF
                aliceKDFunc.keyDerivationSetting().keyDeriveAlgorithm(AlgorithmParameter.AES).done(),
                commonSalt, // alice와 동일한 salt
                commonInfo, // alice와 동일한 info
                32, // alice와 동일한 결과 바이트
                bobReceivedSharedSecret1, bobReceivedSharedSecret2
        );
        log.info("bob측 최종 대칭키 hex: {}", Hex.toHexString(bobKDFSymmetricKeyFinal.asBytes()));

        BlockCipher bobAES = BlockCipher.AES256;
        BlockCipherSettingResult bobAESSettingResult = bobAES.blockCipherSetting()
                .mode(Mode.CBC)
                .padding(Padding.PKCS5)
                .iv(commonIv) // iv만 있으면 됌
                .done();

        // 12. bob의 최종 대칭키로 평문 복호화
        log.info("12. bob의 최종 대칭키로 평문 복호화");
        final byte[] decryptedPlain = BlockCipher.blockCipherDecrypt(
                null,
                encryptedPlain,
                bobKDFSymmetricKeyFinal,
                bobAESSettingResult,
                null,
                0,
                null);

        log.info(new String(decryptedPlain)); // "This is Hybrid Quantum World!!!!!" 가 나오면 성공!
    } // 성공 (2025.01.04)
}