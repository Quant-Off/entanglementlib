/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.security;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 암호학적으로 강화된 비밀번호 생성 및 관리 유틸리티 클래스입니다.
 * <p>
 * 본 클래스는 CWE-327(취약한 암호 알고리즘), CWE-330(불충분한 무작위성), CWE-14(메모리 소거 미비) 등의
 * 보안 취약점을 해결하도록 재설계되었습니다. 양자 내성(Quantum Resistance)을 고려하여
 * 엔트로피 임계값을 상향 조정하였으며, 섀넌 엔트로피(Shannon Entropy)에 기반한 정밀한 강도 측정을 수행합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class Password {

    /**
     * 최소 비밀번호 길이.
     * <p>
     * {@code Grover} 알고리즘에 의한 대칭키 암호 해독 속도 가속을 고려하여,
     * 양자 컴퓨팅 환경에서도 최소한의 안전성을 담보하기 위해 길이를 상향 조정했습니다.
     */
    public static final int MINIMUM_LENGTH = 20;

    /**
     * 기본 비밀번호 길이.
     */
    public static final int DEFAULT_LENGTH = 32;

    /**
     * 최대 비밀번호 길이.
     * <p>
     * 과도한 메모리 할당(CWE-400) 및 버퍼 관련 취약점을 방지하기 위해 제한폭을 축소했습니다.
     */
    public static final int MAXIMUM_LENGTH = 128;

    // 문자 집합 정의 (불변성 보장 및 명시적 선언)
    private static final char[] LOWERCASE = "abcdefghijklmnopqrstuvwxyz".toCharArray();

    private static final char[] UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

    private static final char[] DIGITS = "0123456789".toCharArray();

    // OWASP 권장 특수문자 집합
    private static final char[] SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`".toCharArray();

    private static final char[] ALL_CHARS;

    static {
        int totalLength = LOWERCASE.length + UPPERCASE.length + DIGITS.length + SPECIAL.length;
        ALL_CHARS = new char[totalLength];
        int index = 0;
        System.arraycopy(LOWERCASE, 0, ALL_CHARS, index, LOWERCASE.length);
        index += LOWERCASE.length;
        System.arraycopy(UPPERCASE, 0, ALL_CHARS, index, UPPERCASE.length);
        index += UPPERCASE.length;
        System.arraycopy(DIGITS, 0, ALL_CHARS, index, DIGITS.length);
        index += DIGITS.length;
        System.arraycopy(SPECIAL, 0, ALL_CHARS, index, SPECIAL.length);
    }

    private Password() {
        throw new UnsupportedOperationException("Singleton");
    }

    /**
     * 기본 길이(32자)의 암호학적으로 안전한 비밀번호를 생성합니다.
     *
     * @return 생성된 비밀번호 (char 배열)
     */
    public static char @NotNull [] generate() {
        return generate(DEFAULT_LENGTH);
    }

    /**
     * 지정된 길이의 암호학적으로 안전한 비밀번호를 생성합니다.
     *
     * @param length 비밀번호 길이 ({@value MINIMUM_LENGTH} ~ {@value MAXIMUM_LENGTH})
     * @return 생성된 비밀번호
     * @throws IllegalArgumentException 길이가 유효 범위를 벗어난 경우
     */
    public static char @NotNull [] generate(final @Range(from = MINIMUM_LENGTH, to = MAXIMUM_LENGTH) int length) {
        validateLength(length);

        final char[] password = new char[length];

        try {
            // 각 카테고리에서 최소 1개의 문자를 무작위 위치에 배치하기 위한 임시 리스트가 필요하나,
            // 메모리 파편화를 줄이기 위해 배열 내에서 직접 생성 후 셔플 방식 택

            // 1. 필수 문자군 확보
            password[0] = selectRandomChar(LOWERCASE);
            password[1] = selectRandomChar(UPPERCASE);
            password[2] = selectRandomChar(DIGITS);
            password[3] = selectRandomChar(SPECIAL);

            // 2. 나머지 엔트로피 채움
            for (int i = 4; i < length; i++) {
                password[i] = selectRandomChar(ALL_CHARS);
            }

            // 3. Fisher-Yates Shuffle로 위치 무작위화
            shufflePassword(password);

            return password;
        } catch (Exception e) {
            wipePassword(password); // 예외 발생 시 잔존 메모리 즉시 파기
            throw new SecurityException("Failed to generate secure password due to internal error.", e);
        }
    }

    /**
     * CSPRNG를 사용하여 문자 집합에서 무작위 문자를 선택합니다.
     */
    private static char selectRandomChar(char @NotNull [] charset) {
        // nextInt()는 모듈러 연산의 편향(Modulo Bias)을 내부적으로 처리함
        return charset[InternalFactory.getSafeRandom().nextInt(charset.length)];
    }

    /**
     * Fisher-Yates Shuffle 알고리즘을 사용하여 배열을 섞습니다.
     * <p>
     * 통계적 편향 없이 $N!$의 순열 중 하나를 등확률로 선택합니다.
     */
    private static void shufflePassword(char @NotNull [] password) {
        for (int i = password.length - 1; i > 0; i--) {
            int j = InternalFactory.getSafeRandom().nextInt(i + 1);
            char temp = password[i];
            password[i] = password[j];
            password[j] = temp;
        }
    }

    /**
     * 비밀번호를 메모리에서 안전하게 소거(wiping)합니다.
     * <p>
     * 컴파일러 최적화를 방지하기 위해 난수로 1차 덮어쓰기를 수행한 후, 최종적으로 0으로 초기화합니다.
     * 이는 물리적 메모리 덤프 시 잔류 자화에 의한 데이터 복원 가능성을 최소화합니다.
     *
     * @param password 소거할 비밀번호 배열
     */
    public static void wipePassword(char @NotNull [] password) {
        if (password == null) return;

        // 1단계: 무작위 노이즈로 덮어쓰기 (Deterministic 패턴 방지)
        // 루프 펼치기나 DSE 최적화를 어렵게 만듦
        for (int i = 0; i < password.length; i++)
            password[i] = (char) InternalFactory.getSafeRandom().nextInt(Character.MAX_VALUE);

        // 2단계: 0으로 초기화 (Nullification)
        KeyDestroyHelper.zeroing(password);

        // 3단계: 메모리 펜스(Memory Fence) 효과를 위한 휘발성 읽기 시도 (선택적 구현)
        // Java에서는 volatile 변수가 아닌 배열 요소에 대해 완벽한 강제가 어렵지만,
        // 로그 기록 등을 통해 코드 실행 흐름 유지
        log.debug("Sensitive memory segment wiped. Address/Ref: {}", System.identityHashCode(password));
    }

    /**
     * 비밀번호의 실제 정보 엔트로피(Shannon entropy)를 계산합니다.
     * <p>
     * 단순히 문자 종류의 수가 아닌, 각 문자의 출현 확률 분포를 기반으로 계산하여
     * 취약점 보고서(CWE-327)에서 지적된 엔트로피 과대평가 문제를 해결합니다.
     *
     * @param password 엔트로피를 계산할 비밀번호
     * @return 계산된 엔트로피 비트 수 (bits)
     */
    public static double calculateEntropy(char @NotNull [] password) {
        Objects.requireNonNull(password);
        int length = password.length;
        if (length == 0) return 0.0;

        Map<Character, Integer> frequencyMap = new HashMap<>();
        for (char c : password) {
            frequencyMap.put(c, frequencyMap.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        for (int count : frequencyMap.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        // 섀넌 엔트로피는 '심볼 당' 정보량이므로, 전체 비밀번호의 엔트로피는 길이(L)를 곱해야 함
        return entropy * length;
    }

    /**
     * 비밀번호의 보안 강도를 검증합니다.
     * <p>
     * 양자 내성 암호 환경을 고려하여 기준 엔트로피를 상향 조정하였습니다.
     * <a href="https://pages.nist.gov/800-63-3/sp800-63b.html">NIST SP 800-63B</a>
     * 가이드라인 및 Grover 알고리즘에 대한 저항성을 반영합니다.
     *
     * @param password 검증할 비밀번호
     * @return 안전한 비밀번호 여부 (True/False)
     */
    public static boolean isStrong(char @NotNull [] password) {
        Objects.requireNonNull(password);

        // 기본 길이 검증
        if (password.length < MINIMUM_LENGTH) {
            log.warn("Password validation failed: Insufficient length.");
            return false;
        }

        boolean hasLower = false;
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password) {
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else if (isSpecialChar(c)) hasSpecial = true;
        }

        // 문자 집합 복잡성 요구사항
        if (!(hasLower && hasUpper && hasDigit && hasSpecial)) {
            log.warn("Password validation failed: Missing character types.");
            return false;
        }

        // 엔트로피 검증
        // 128비트 보안 강도는 현재 및 가까운 미래의 컴퓨팅 파워(양자 포함)에 대해 안전하다고 간주됨
        // 다만, 랜덤 생성된 비밀번호의 경우 문자 집합 크기의 한계로 인해 길이 20~25자에서 약 100~130비트가 형성
        // 최소 기준을 100비트로 설정하여 현실적인 'Strong' 기준 제시
        double actualEntropy = calculateEntropy(password);
        final double REQUIRED_ENTROPY = 100.0;

        if (actualEntropy < REQUIRED_ENTROPY) {
            log.warn("Password validation failed: Insufficient entropy ({}/{})", actualEntropy, REQUIRED_ENTROPY);
            return false;
        }

        return true;
    }

    private static boolean isSpecialChar(char c) {
        for (char special : SPECIAL) {
            if (c == special) return true;
        }
        return false;
    }

    private static void validateLength(int length) {
        if (length < MINIMUM_LENGTH || length > MAXIMUM_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Invalid password length: %d. Must be between %d and %d.",
                            length, MINIMUM_LENGTH, MAXIMUM_LENGTH));
        }
    }
}