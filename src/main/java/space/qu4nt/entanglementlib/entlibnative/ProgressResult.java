/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.entlibnative;

import lombok.Getter;

import java.util.Arrays;

@Getter
public enum ProgressResult {

    SUCCESS(0),
    CALC_FAILURE(-1),
    JUST_FAILURE(-2);

    private final int code;

    ProgressResult(int code) {
        this.code = code;
    }

    public boolean isFail() {
        return this.code != 0;
    }

    public static ProgressResult fromCode(final int code) {
        return Arrays.stream(ProgressResult.values())
                .filter(i -> i.getCode() == code)
                .findFirst()
                .orElseThrow();
    }
}
