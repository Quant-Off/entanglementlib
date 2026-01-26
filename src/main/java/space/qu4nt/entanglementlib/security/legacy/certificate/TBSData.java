/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.legacy.certificate;

import lombok.Builder;
import lombok.Data;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureCertProcessException;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

@Data
@Builder
public class TBSData {

    private short certificateVersion;

    @NotNull
    private SubjectString issuer;

    @Nullable
    private BigInteger serialNumber;

    @Nullable
    private Instant notBefore;

    @Nullable
    private Instant notAfter;

    @Nullable
    private SubjectString subject;

    @NotNull
    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    @SuppressWarnings({"all"})
    public X509CertificateHolder toX509v3Certificate(final @NotNull String algorithm,
                                                     final @NotNull PrivateKey sk,
                                                     boolean isRootCA)
            throws EntLibSecureCertProcessException {
        Objects.requireNonNull(algorithm);
        Objects.requireNonNull(sk);
        Objects.requireNonNull(issuer);
        Objects.requireNonNull(subjectPublicKeyInfo);

        if (certificateVersion != 3)
            throw new EntLibSecureCertProcessException(TBSData.class, "unsupported-ver-exc", null, certificateVersion);

        // serialNumber
        if (serialNumber == null)
            serialNumber = new BigInteger(10, InternalFactory.getSafeRandom());

        // notBefore
        if (notBefore == null)
            notBefore = Instant.now();

        // notAfter
        if (notAfter == null)
            notAfter = Instant.now().plus(365, ChronoUnit.DAYS);

        // subject
        if (subject == null) // issuer와 동일하다 간주
            subject = issuer;

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder
                (issuer.toX500Name(), serialNumber, Date.from(notBefore), Date.from(notAfter), subject.toX500Name(), subjectPublicKeyInfo);

        ContentSigner signer;
        try {
            if (isRootCA) {
                // BasicConstraints 확장 CA=true, pathLen 무제한
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
                // KeyUsage: Certificate Signing, CRL Signing
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            } else {
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                // KeyUsage: digitalSignature (TLS 핸드셰이크 서명용 필수)
                // TODO: 나중에 keyEncipherment 추가 고려 (RSA 등의 경우이나, TLS 1.3 + PQC에서는 digitalSignature가 핵심)
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
                // ExtendedKeyUsage: serverAuth (TLS 서버 인증용)
                builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            }

            signer = new JcaContentSignerBuilder(algorithm)
                    .setProvider(InternalFactory.getBCNormalProvider())
                    .build(sk);
        } catch (OperatorCreationException | CertIOException e) {
            throw new EntLibSecureCertProcessException(e);
        }

        return builder.build(signer);
    }

    public static boolean isCertificateValid(
            final @NotNull X509CertificateHolder certHolder,
            final @NotNull PublicKey publicKey) throws Exception {
        certHolder.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .setProvider(InternalFactory.getBCNormalProvider())
                .build(publicKey));
        return true;
    }

}
