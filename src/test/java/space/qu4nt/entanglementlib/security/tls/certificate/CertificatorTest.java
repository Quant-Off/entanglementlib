/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.algorithm.MLDSA;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;
import space.qu4nt.entanglementlib.security.algorithm.SLHDSA;
import space.qu4nt.entanglementlib.security.algorithm.SLHDSAType;
import space.qu4nt.entanglementlib.security.tls.certificate.Certificator;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

class CertificatorTest {

    @Test
    void test() {
        // SLH-DSA 세션
        try (SLHDSA slhdsa = SLHDSA.create(SLHDSAType.SLH_DSA_SHAKE_256s, "root")) {
            KeyPair rootPair = slhdsa.generateEntKeyPair().keyPair();
            final X509Certificate rootCA = Certificator.generateRootCACertificate(
                    slhdsa.getType(),
                    rootPair.getPublic(),
                    rootPair.getPrivate(),
                    Certificator.DEFAULT_ROOT_CA_QCR3_TBS);
            System.out.println("SLH-DSA 루트 CA 생성 완료");

            // ML-DSA 알고리즘 세션
            try (MLDSA mldsa = MLDSA.create(MLDSAType.ML_DSA_87, "server")) {
                KeyPair mldsaPair = mldsa.generateEntKeyPair().keyPair();
                final X509Certificate serverCert = Certificator.generateCAChainCertificate(
                        Certificator.DEFAULT_ROOT_CA_QCR3_TBS,
                        Certificator.DEFAULT_SERVER_RiS_TBS,
                        slhdsa.getType(),  // SLH-DSA 타입으로 수정
                        mldsaPair.getPublic(),  // 서버 공개 키는 ML-DSA
                        rootPair.getPrivate());  // 루트 CA 개인 키 (SLH-DSA)
                System.out.println("ML-DSA 인증서 체인 생성 완료");

                serverCert.verify(rootPair.getPublic());
                System.out.println("ML-DSA 인증서 검증 완료");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}