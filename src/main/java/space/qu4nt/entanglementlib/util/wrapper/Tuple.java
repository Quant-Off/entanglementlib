/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.wrapper;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 세 개의 타입을 래핑하는 클래스입니다.
 *
 * @param <F> 첫 번째 타입
 * @param <S> 두 번째 타입
 * @param <T> 세 번째 타입
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Tuple<F, S, T> {

    private F first;
    private S second;
    private T third;

    public void set(F first, S second, T third) {
        this.first = first;
        this.second = second;
        this.third = third;
    }
}
