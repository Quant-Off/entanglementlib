/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.core.util.wrapper;

/**
 * 두 개의 타입을 래핑하는 클래스입니다.
 *
 * @param <F> 첫 번째 타입
 * @param <S> 두 번째 타입
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class Pair<F, S> {

    private F first;
    private S second;

    public Pair() {
    }

    public Pair(F first, S second) {
        this.first = first;
        this.second = second;
    }

    public void set(F first, S second) {
        this.first = first;
        this.second = second;
    }

    public F getFirst() {
        return first;
    }

    public void setFirst(F first) {
        this.first = first;
    }

    public S getSecond() {
        return second;
    }

    public void setSecond(S second) {
        this.second = second;
    }
}
