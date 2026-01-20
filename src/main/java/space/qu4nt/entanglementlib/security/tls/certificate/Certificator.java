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

package space.qu4nt.entanglementlib.security.tls.certificate;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * 인증서 생성을 위한 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public class Certificator {

    public static final SubjectString DEFAULT_ROOT_CA_QCR3_TBS;

    public static final SubjectString DEFAULT_SERVER_RiS_TBS;

    static {
        DEFAULT_ROOT_CA_QCR3_TBS = SubjectString.builder()
                .commonName("BlueBridge QCR3 R")
                .organization("Quant")
                .organizationalUnit("GlobalSign Root Internal Units")
                .country("KR")
                .locality("Seoul-si")
                .stateOrProvince("Gangnam-gu")
                .build();
        DEFAULT_SERVER_RiS_TBS = SubjectString.builder()
                .commonName("BlueBridge QCR3 RiS")
                .organization("Quant")
                .organizationalUnit("GlobalSign Units")
                .country("KR")
                .locality("Seoul-si")
                .stateOrProvince("Gangnam-gu")
                .build();
    }

    /**
     * 지정된 알고리즘으로 X509 루트 CA 인증서를 생성하는 메소드입니다.
     * <p>
     * 루트 CA 인증서는 자체 서명되며, {@code BasicConstraints} 확장을 포함하여 CA로서의 역할을 명시합니다.
     *
     * @param type          사용할 알고리즘
     * @param pk            공개 키
     * @param sk            비밀 키
     * @param subjectString 인증서 발급 정보
     * @return 생성된 X509 루트 CA 인증서
     * @throws OperatorCreationException 인증서 홀더 객체를 사용하여 인증서를 생성하는 도중 예외가 발생한 경우
     * @throws CertificateException      컨버터 객체를 통해 인증서 객체를 생성하는 도중 예외가 발생한 경우
     * @throws CertIOException           인증서에 확장을 추가하는 도중 예외가 발생한 경우
     */
    public static X509Certificate generateRootCACertificate(@NotNull EntLibParameterSpec type,
                                                            @NotNull PublicKey pk,
                                                            @NotNull PrivateKey sk,
                                                            @NotNull SubjectString subjectString)
            throws Exception {
        Objects.requireNonNull(type);
        Objects.requireNonNull(pk);
        Objects.requireNonNull(sk);
        Objects.requireNonNull(subjectString);

        // PublicKey to SubjectPublicKeyInfo with BouncyCastle
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pk.getEncoded());
        final TBSData certInfo = TBSData.builder()
                .certificateVersion((short) 3)
                .issuer(subjectString)
                .subjectPublicKeyInfo(pkInfo)
                .build();
        final X509CertificateHolder holder = certInfo.toX509v3Certificate(type.getAlgorithmName(), sk, true);
        return new JcaX509CertificateConverter()
                .setProvider(InternalFactory.getBCNormalProvider())
                .getCertificate(holder);
    }

    /**
     * 루트 CA 인증서의 주체 정보를 사용하여 새로운 X509 인증서를 생성하는 메소드입니다.
     *
     * @param rootSubjectDN  루트 주체 정보
     * @param newerSubjectDN 생성자 주체 정보
     * @param type           사용할 알고리즘
     * @param newerPk        생성자 공개 키
     * @param rootSk         루트 비밀 키
     * @return X509 루트 CA 주체 정보로 서명된 인증서
     * @throws OperatorCreationException 인증서 홀더 객체를 사용하여 인증서를 생성하는 도중 예외가 발생한 경우
     * @throws CertificateException      컨버터 객체를 통해 인증서 객체를 생성하는 도중 예외가 발생한 경우
     * @throws CertIOException           인증서에 확장을 추가하는 도중 예외가 발생한 경우
     */
    public static X509Certificate generateCAChainCertificate(@NotNull SubjectString rootSubjectDN,
                                                             @NotNull SubjectString newerSubjectDN,
                                                             @NotNull EntLibParameterSpec type,
                                                             @NotNull PublicKey newerPk,
                                                             @NotNull PrivateKey rootSk)
            throws Exception {
        Objects.requireNonNull(rootSubjectDN);
        Objects.requireNonNull(newerSubjectDN);
        Objects.requireNonNull(type);
        Objects.requireNonNull(newerPk);
        Objects.requireNonNull(rootSk);

        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(newerPk.getEncoded());
        final TBSData certInfo = TBSData.builder()
                .certificateVersion((short) 3)
                .issuer(rootSubjectDN)
                .subject(newerSubjectDN)
                .subjectPublicKeyInfo(pkInfo)
                .build();
        final X509CertificateHolder holder = certInfo.toX509v3Certificate(type.getAlgorithmName(), rootSk, false);
        return new JcaX509CertificateConverter()
                .setProvider(InternalFactory.getBCNormalProvider())
                .getCertificate(holder);
    }

}
