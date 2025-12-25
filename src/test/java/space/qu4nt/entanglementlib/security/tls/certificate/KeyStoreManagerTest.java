/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.PostQuantumParameterSpec;
import space.qu4nt.entanglementlib.security.algorithm.MLDSA;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;
import space.qu4nt.entanglementlib.util.wrapper.Tuple;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class KeyStoreManagerTest {

    /// # Truststore
    /// -     root-slh-dsa-ca-cert : 루트 ca 인증서
    /// # Keystore
    /// -     server-ml-dsa : 서버 비밀 키 <> 체인(서버 공개 키/루트 ca 인증서)
    /// -     root-ca-sk    : 루트 비밀 키
    @Test
    void test() throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        // 단계 1: KeyStoreManager 인스턴스 생성 (기본 BCFKS 타입 사용, BouncyCastle 지원)
        final KeyStoreManager manager = new KeyStoreManager();
        // 루트 전용 키스토어 인스턴스 생성
        final KeyStoreManager rootManager = new KeyStoreManager();

        final MLDSAType rootType = MLDSAType.ML_DSA_87_WITH_SHA512;

        Tuple<X509Certificate, PublicKey, PrivateKey> root = rootCA(rootType);
        Tuple<X509Certificate, PublicKey, PrivateKey> serv = serverCert(rootType, root.getThird());

        // 단계 2: 파일 경로와 비밀번호 설정
        char[] commonPass = "secret".toCharArray();
        Path rootPath = Paths.get(InternalFactory.envEntanglementHomeDir(), "temp-root-keystore.bcfks");
        Path path = Paths.get(InternalFactory.envEntanglementHomeDir(), "temp-keystore.bcfks");
        Path tpath = Paths.get(InternalFactory.envEntanglementHomeDir(), "temp-truststore.bcfks");

        // 단계 3: Keystore와 Truststore 로드 (파일 없으면 빈 상태로 초기화)
        rootManager.loadKeyStore(rootPath, commonPass.clone());
        System.out.println("루트 키스토어 로드 완료");
        manager.loadKeyStore(path, commonPass.clone());
        System.out.println("키스토어 로드 완료");
        manager.loadTrustStore(tpath, commonPass.clone());
        System.out.println("트러스트스토어 로드 완료");

        // 단계 4: 루트 CA 인증서 트러스트스토어에 저장
        manager.setTruststoreCertificateEntry("root-ml-dsa-ca-cert", root.getFirst());
        System.out.println("루트 인증서 트러스트스토어에 저장 완료");

        // 단계 5: 서버 인증서와 키 페어 저장 (Keystore에 추가: 개인 키와 인증서 체인 함께)
        Certificate[] chain = new Certificate[]{serv.getFirst()};
        manager.setKeyEntry("server-ml-dsa", serv.getThird(), commonPass.clone(), chain);
        System.out.println("서버 인증서와 키 페어 키스토어에 저장 완료");

        // TODO: 선택적이지만 루트 CA 개인 키 저장 (Keystore에, 이는 CA 운영 시 별도 HSM 권장
        rootManager.setKeyEntry("root-ca-sk", root.getThird(), commonPass.clone(), new Certificate[]{root.getFirst()});
        System.out.println("루트 인증서에 사용된 비밀 키 루트 키스토어에 저장 완료");

        // 단계 6: 변경 사항 저장 (원자적 저장으로 안정성 보장)
        rootManager.storeKeyStore(commonPass.clone());
        manager.storeKeyStore(commonPass.clone());
        manager.storeTrustStore(commonPass.clone());
        System.out.println("인증서와 키 페어 저장 완료");
    } // 통과

    private Tuple<X509Certificate, PublicKey, PrivateKey> rootCA(PostQuantumParameterSpec rootType) {
        try (MLDSA mldsa = MLDSA.create((MLDSAType) rootType, "root")) {
            KeyPair rootPair = mldsa.generateEntKeyPair().keyPair();
            final X509Certificate rootCA = Certificator.generateRootCACertificate(
                    mldsa.getType(),
                    rootPair.getPublic(),
                    rootPair.getPrivate(),
                    Certificator.DEFAULT_ROOT_CA_QCR3_TBS);
            System.out.println("ML-DSA-65 (sha512) 루트 CA 생성 완료");
            return new Tuple<>(rootCA, rootPair.getPublic(), rootPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Tuple<X509Certificate, PublicKey, PrivateKey> serverCert(PostQuantumParameterSpec rootType, PrivateKey rootSK) {
        final Tuple<X509Certificate, PublicKey, PrivateKey> t = new Tuple<>();
        try (MLDSA mldsa = MLDSA.create(MLDSAType.ML_DSA_65_WITH_SHA512, "server")) {
            KeyPair serverPair = mldsa.generateEntKeyPair().keyPair();
            final X509Certificate serverCert = Certificator.generateCAChainCertificate(
                    Certificator.DEFAULT_ROOT_CA_QCR3_TBS,
                    Certificator.DEFAULT_SERVER_RiS_TBS,
                    rootType,
                    serverPair.getPublic(),
                    rootSK);  // 루트 CA 개인 키
            System.out.println("ML-DSA-65 (sha512) 인증서 체인 생성 완료");
            t.set(serverCert, serverPair.getPublic(), serverPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return t;
    }

}