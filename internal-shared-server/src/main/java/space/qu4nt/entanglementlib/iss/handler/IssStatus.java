/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;

/// 애플리케이션 응답 상태 코드입니다.
///
/// @author Q. T. Felix
public enum IssStatus {

    OK((byte) 0),
    NOT_FOUND((byte) 1),
    ERROR((byte) 2),
    UNKNOWN_COMMAND((byte) 3),
    BAD_REQUEST((byte) 4);

    private final byte code;

    IssStatus(final byte code) {
        this.code = code;
    }

    public byte code() {
        return code;
    }

    public boolean isOk() {
        return this == OK;
    }

    public static @NotNull IssStatus from(final byte code) {
        for (final IssStatus s : values()) {
            if (s.code == code)
                return s;
        }
        return ERROR;
    }
}
