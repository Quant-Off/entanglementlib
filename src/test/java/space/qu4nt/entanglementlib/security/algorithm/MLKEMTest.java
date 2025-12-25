/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import space.qu4nt.entanglementlib.util.wrapper.Hex;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import javax.crypto.SecretKey;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 뭐하는 테스트 클래스임?
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
class MLKEMTest {

    static MLKEM mlkem;

    @Test
    @DisplayName("ML-KEM 테스트")
    void mlkemTest() throws Exception {
        mlkem = MLKEM.create(MLKEMType.ML_KEM_768, "Hello, Secure World!");
        final KeyPair pair = mlkem.generateEntKeyPair().keyPair();

        // 1. 캡슐화
        Pair<byte[], SecretKey> capsule = mlkem.encapsulate(pair.getPublic());
        log.info("KEM 캡슐 암호문: {}", Hex.toHexString(capsule.getFirst()));
        log.info("KEM 캡슐 공유 비밀: {}", Hex.toHexString(capsule.getSecond().getEncoded()));

        // 2. 디캡슐화
        byte[] receivedSharedSecret = mlkem.decapsulate(capsule.getSecond(), pair.getPrivate(), capsule.getFirst());
        log.info("KEM 수신 공유 비밀: {}", Hex.toHexString(receivedSharedSecret));

        assertEquals(Hex.toHexString(capsule.getSecond().getEncoded()), Hex.toHexString(receivedSharedSecret), "송/수신값이 일치하지 않음");
    }

    @AfterAll
    static void tearDown() throws Exception {
        mlkem.close();
    }

}