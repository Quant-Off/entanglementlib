/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.lang.foreign.MemorySegment;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * 키 데이터를 영소거(zeroing)하기 위한 몇 가지 도구를 제공하는 클래스입니다.
 * 소거된 키는 공격자가 배열 정보를 알 수 없도록 리플렉션을 통해 완전히 제거하고,
 * 소거 후 배열 사이즈를 {@code 0}으로 초기화합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class KeyDestroyHelper {

    private static final LanguageInstanceBased<KeyDestroyHelper> lang =
            LanguageInstanceBased.create(KeyDestroyHelper.class);

    /**
     * 리플렉션을 통해 전달받은 객체 타입의 필드를 영소거하는 메소드입니다.
     * 내부 인스턴스의 모든 필드를 검사하여 민감한 데이터({@code byte[]},
     * {@code char[]}, {@code SecretKey})가 해당됩니다.
     * <p>
     * 단, {@link javax.crypto.SecretKey} 객체를 구현하는
     * {@link javax.crypto.spec.SecretKeySpec} 객체의 경우,
     * JPMS 보안 시스템이 강화되어 리플렉션으로도 접근할 수 없습니다.
     *
     * @param targetObject 소거할 내부 키 파라미터 객체
     * @deprecated 1.1.0 이상 버전부턴 모든 메모리 관련 기능이 {@code entlib-native}를 통해 구현됩니다.
     */
    @Deprecated
    public static void destroy(Object targetObject) {
        if (targetObject == null) return;

        // 순환 참조 방지를 위해 방문한 객체의 주소값을 저장 (IdentityHashMap 사용)
        Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        recursiveZeroing(targetObject, visited, false);
    }

    /**
     * 리플렉션을 통해 전달받은 객체 타입의 필드를 영소거하는 메소드입니다.
     * 얕은 소거(shallow)를 활성화하면 해당 객체의 필드만 소거하고 재귀적으로 탐색하지 않습니다.
     *
     * @param targetObject 소거할 내부 키 파라미터 객체
     * @param shallow      얕은 소거 여부, 재귀 탐색을 원치 않으면 true, 그렇지 않으면 false
     * @deprecated 1.1.0 이상 버전부턴 모든 메모리 관련 기능이 {@code entlib-native}를 통해 구현됩니다.
     */
    @Deprecated
    public static void destroy(Object targetObject, boolean shallow) {
        if (targetObject == null) return;

        Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        recursiveZeroing(targetObject, visited, shallow);
    }

    /**
     * @deprecated 1.1.0 이상 버전부턴 모든 메모리 관련 기능이 {@code entlib-native}를 통해 구현됩니다.
     */
    @Deprecated
    private static void recursiveZeroing(Object targetObject, Set<Object> visited, boolean shallow) {
        if (targetObject == null) return;

        // JPMS 보안 강화로 인해 리플렉션 불가능
        // TODO: 대칭 키 객체 소거 방안 찾기
        if (targetObject instanceof SecretKeySpec s) {
            try {
                s.destroy();
            } catch (DestroyFailedException e) {
                zeroing(s.getEncoded()); // 대안이 생기기 전 까진 복사본이라도 소거
            }
            return;
        }

        // 이미 방문한 객체인지 확인 (무한 루프 방지)
        if (visited.contains(targetObject)) return;
        visited.add(targetObject);

        Class<?> currentClass = targetObject.getClass();

        // 탐색 제외 조건 (Java 내부 클래스나 원시 타입 래퍼 등은 내부를 탐색할 필요 없음)
        // 단, byte[]는 배열이므로 여기서 걸러지지 않도록 주의 (isArray 체크는 아래에서 함)
        if (isSkippingType(currentClass)) {
            return;
        }

        // 현재 클래스와 모든 부모 클래스의 필드를 탐색
        while (currentClass != null && currentClass != Object.class) {
            Field[] fields = currentClass.getDeclaredFields();

            for (Field field : fields) {
                try {
                    // static 필드는 제외
                    if (Modifier.isStatic(field.getModifiers())) continue;

                    field.setAccessible(true);
                    Object value = field.get(targetObject);

                    if (value == null) continue;

                    // 타겟 발견 소거 수행
                    if (field.getType() == byte[].class) {
                        zeroing((byte[]) value);
                        field.set(targetObject, new byte[0]);
                        log.debug(lang.argsNonTopKey("debug-byte-arr-field-zeroing-result", field.getName(), Hex.toHexString((byte[]) field.get(targetObject))));
                    } else if (field.getType() == char[].class) {
                        zeroing((char[]) value);
                        field.set(targetObject, new char[0]);
                        log.debug(lang.argsNonTopKey("debug-char-arr-field-zeroing-result", field.getName(), Arrays.toString((char[]) field.get(targetObject))));
                    } else if (field.getType() == BigInteger.class) {
                        field.set(targetObject, new BigInteger(0, new byte[0]));
                        log.debug(lang.argsNonTopKey("debug-number-field-zeroing-result", field.getName(), field.get(targetObject)));
                    } else if (field.getType() == Number.class) {
                        field.set(targetObject, 0);
                        log.debug(lang.argsNonTopKey("debug-number-field-zeroing-result", field.getName(), field.get(targetObject)));
                    }
                    // 배열만 재귀 탐색
                    else if (!shallow && !field.getType().isPrimitive() && !field.getType().isArray()) {
                        recursiveZeroing(value, visited, false);
                    }

                } catch (IllegalAccessException e) {
                    log.error(lang.msg("cannot-access-exc"), e);
                }
            }
            // 부모 클래스로 이동하여 필드 탐색 계속
            currentClass = currentClass.getSuperclass();
        }
    }

    // 탐색을 멈출 타입 정의 (String, Number 등 불변 객체거나 내부 필드가 의미 없는 경우)
    @Deprecated
    private static boolean isSkippingType(Class<?> clazz) {
        if (clazz == null) return true;
        String name = clazz.getName();
        return clazz.isPrimitive() ||
                name.startsWith("java.lang.") ||
                name.startsWith("java.util.") ||
                name.startsWith("java.math.");
    }

    /**
     * 메모리에서 바이트 배열을 안전하게 영소거하는 메소드입니다.
     *
     * @param bytes 영소거할 바이트 배열
     */
    public static void zeroing(byte @NotNull [] bytes) {
        Arrays.fill(bytes, (byte) 0);
    }

    /**
     * 메모리에서 2차원 바이트 배열을 안전하게 영소거하는 메소드입니다.
     *
     * @param bytes2d 영소거할 2차원 바이트 배열
     */
    public static void zeroing(byte[][] bytes2d) {
        for (byte[] bytes : bytes2d)
            zeroing(bytes);
    }

    /**
     * 메모리에서 문자 배열을 안전하게 영소거하는 메소드입니다.
     *
     * @param chars 영소거할 문자 배열
     */
    public static void zeroing(char @NotNull [] chars) {
        Arrays.fill(chars, '\0');
    }

    /**
     * 메모리에서 2차원 바이트 배열을 안전하게 영소거하는 메소드입니다.
     *
     * @param chars2d 영소거할 2차원 바이트 배열
     */
    public static void zeroing(char[][] chars2d) {
        for (char[] chars : chars2d)
            zeroing(chars);
    }

    /// 네이티브 메모리에 할당된 데이터를 영소거하는 메소드입니다.
    ///
    /// @param memorySegment 영소거할 메모리 타겟
    public static void zeroing(final MemorySegment memorySegment) {
        memorySegment.fill((byte) 0);
    }
}
