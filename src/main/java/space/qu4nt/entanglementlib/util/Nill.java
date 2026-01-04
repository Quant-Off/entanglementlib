/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util;

import java.util.function.Supplier;

/**
 * 이 클래스는 객체가 {@code null} 인지 아닌지를 판단하기 위한 클래스입니다.
 * 객체의 {@code null} 여부를 체크하는 메소드를 포함합니다.
 * <p>
 * {@code Nill} 클래스는 Stateless 하므로, 모든 메소드는 정적으로 작성되어야 합니다.
 * 따라서 이 클래스의 인스턴스를 만드는 것은 불가능합니다.
 * <p>
 * 다음과 같이 사용할 수 있습니다.
 * <pre>{@code
 * import com.quant.bluebridge.core.util.Nill;
 *
 * class Main {
 *     public static void main(String[] args) {
 *         // 객체의 단순 null 여부 체크
 *         if (Nill.isNull(obj)) {
 *             // ... 객체가 null일 때 작업
 *         } else {
 *             // ... 객체가 null이 아닐 때 작업
 *         }
 *
 *         // 객체가 null이 아닐 경우 Runnable을 사용한 작업 수행
 *         Null.isNot(obj, () -> {
 *            // ... 작업
 *         });
 *
 *         // 객체가 null인 경우 Runnable을 사용한 작업 수행
 *         Null.ifSo(obj, () -> {
 *            // ... 작업
 *         });
 *     }
 * }
 * }</pre>
 * 이 클래스는 특정 함수에서 {@code null}에 대응할 때 메소드 참조 패턴으로
 * 간편히 대응할 수 있도록 하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
public final class Nill {

    // Singleton
    private Nill() {
        throw new UnsupportedOperationException("Singleton");
    }

    /**
     * 전달받은 객체가 {@code null}이 아닐 경우, runnable 작업을 수행하는 메소드입니다.
     *
     * @param obj      검사 대상 객체
     * @param runnable 수행할 작업
     * @param <T>      타입 파라미터
     */
    public static <T> void ifNot(final T obj, final Runnable runnable) {
        if (!isNull(obj))
            runnable.run();
    }

    /**
     * 전달받은 객체가 {@code null}일 경우, runnable 작업을 수행하는 메소드입니다.
     *
     * @param obj      검사 대상 객체
     * @param runnable 수행할 작업
     * @param <T>      타입 파라미터
     */
    public static <T> void ifSo(final T obj, final Runnable runnable) {
        if (isNull(obj))
            runnable.run();
    }

    /**
     * 전달받은 객체가 {@code null}일 경우, {@link Supplier} 작업을 수행하고
     * 결과를 반환하는 메소드입니다. 전달받은 객체가 null이 아니면 객체를 순수히
     * 전달합니다.
     *
     * @param obj      검사 대상 객체
     * @param supplier 수행할 작업
     * @param <T>      타입 파라미터
     * @return 결과
     */
    public static <T> T nullDef(final T obj, final Supplier<T> supplier) {
        if (isNull(obj))
            return supplier.get();
        return obj;
    }

    /**
     * 전달받은 객체가 {@code null}인지 검사하는 메소드입니다.
     *
     * @param obj 검사 대상 객체
     * @param <T> 타입 파라미터
     * @return obj가 {@code null}인 경우 true, 아닌 경우 false
     */
    public static <T> boolean isNull(final T obj) {
        return obj == null;
    }

}