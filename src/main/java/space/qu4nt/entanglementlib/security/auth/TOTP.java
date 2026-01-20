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

package space.qu4nt.entanglementlib.security.auth;

import org.jetbrains.annotations.Range;
import space.qu4nt.entanglementlib.security.algorithm.Digest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

/**
 * 상태를 가지지 않는 TOTP(Time-based One-Time Password) 2FA를 제공하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
public final class TOTP {

    /**
     * 현재 시간을 기준으로 TOTP 코드를 생성하는 메소드입니다.
     *
     * @param digest          해시 알고리즘
     * @param digit           TOTP 코드의 자릿수
     * @param timeStepSeconds 시간 간격(초)
     * @param secretKeyBase64 {@code Base64}로 인코딩된 비밀키
     * @return 생성된 TOTP 코드
     */
    public static String generateCurrentTotp(Digest digest, int digit, final long timeStepSeconds, String secretKeyBase64) {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        long timeStep = currentTimeSeconds / timeStepSeconds;

        return computeTotp(digest, digit, secretKeyBase64, timeStep);
    }

    /**
     * 입력된 TOTP 코드를 검증하는 메소드입니다.
     * 네트워크 지연 등을 고려하여 현재 스텝과 이전 스텝까지 유효성을 확인합니다.
     *
     * @param digest          해시 알고리즘
     * @param digit           TOTP 코드의 자릿수
     * @param timeStepSeconds 시간 간격(초)
     * @param secretKeyBase64 {@code Base64}로 인코딩된 비밀키
     * @param inputCode       검증할 TOTP 코드
     * @return 검증 성공 여부
     */
    public static boolean verifyTotp(Digest digest, int digit, final long timeStepSeconds, String secretKeyBase64, String inputCode) {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        long currentTimeStep = currentTimeSeconds / timeStepSeconds;

        // 네트워크 지연 등을 고려해 현재 스텝과 바로 이전 스텝까지 유효하다고 판단
        for (int i = -1; i <= 0; i++) {
            String generated = computeTotp(digest, digit, secretKeyBase64, currentTimeStep + i);
            if (generated.equals(inputCode)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 주어진 시간 스텝과 비밀키를 사용하여 TOTP 코드를 계산하는 내부 메소드입니다.
     *
     * @param digest          해시 알고리즘
     * @param digit           TOTP 코드의 자릿수
     * @param secretKeyBase64 {@code Base64}로 인코딩된 비밀키
     * @param timeStep        시간 스텝
     * @return 계산된 TOTP 코드
     */
    private static String computeTotp(Digest digest,
                                      @Range(from = 6, to = Integer.MAX_VALUE) int digit,
                                      String secretKeyBase64,
                                      long timeStep) {
        try {
            byte[] secretKey = Base64.getDecoder().decode(secretKeyBase64);

            // TimeStep을 8바이트 배열로 변환
            byte[] data = new byte[8];
            for (int i = 8; i-- > 0; timeStep >>>= 8) {
                data[i] = (byte) timeStep;
            }

            final String alg = "Hmac" + digest.getName();
            Mac mac = Mac.getInstance(alg);
            mac.init(new SecretKeySpec(secretKey, alg));
            byte[] hash = mac.doFinal(data);

            // 동적 Truncation
            int offset = hash[hash.length - 1] & 0xF;
            long binary =
                    ((hash[offset] & 0x7f) << 24) |
                            ((hash[offset + 1] & 0xff) << 16) |
                            ((hash[offset + 2] & 0xff) << 8) |
                            (hash[offset + 3] & 0xff);

            long otp = binary % (long) Math.pow(10, digit);

            // 0 패딩
            return String.format("%0" + digit + "d", otp);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("TOTP Generation Error", e);
        }
    }

}
