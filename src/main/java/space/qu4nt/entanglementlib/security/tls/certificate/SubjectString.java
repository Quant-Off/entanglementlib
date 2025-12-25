/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import lombok.Builder;
import lombok.Data;
import org.bouncycastle.asn1.x500.X500Name;

@Data
@Builder
public class SubjectString {

    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String locality;
    private String stateOrProvince;

    /**
     * {@code BouncyCastle} 라이브러리를 사용하여 주체 문자열을
     * {@code X.500} 타입으로 변환하는 메소드입니다.
     * <p>
     * 해당 라이브러리가 의존성으로 등록되어 있지 않다면 기능을 사용할 수 없습니다.
     *
     * @return X.500 타입
     */
    public X500Name toX500Name() {
        return new X500Name(toString());
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();

        if (valid(commonName)) {
            result.append("CN=").append(commonName).append(", ");
        }
        if (valid(organization)) {
            result.append("O=").append(organization).append(", ");
        }
        if (valid(organizationalUnit)) {
            result.append("OU=").append(organizationalUnit).append(", ");
        }
        if (valid(country)) {
            result.append("C=").append(country).append(", ");
        }
        if (valid(locality)) {
            result.append("L=").append(locality).append(", ");
        }
        if (valid(stateOrProvince)) {
            result.append("ST=").append(stateOrProvince).append(", ");
        }

        if (!result.isEmpty() && result.toString().endsWith(", ")) {
            return result.substring(0, result.length() - 2);
        }
        return result.toString();
    }

    private boolean valid(String s) {
        return s != null && !s.isEmpty();
    }
}
