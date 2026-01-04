/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security.builder;

import lombok.Builder;
import lombok.Getter;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

/**
 * {@code AEAD} 지원을 위한 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Builder
@ApiStatus.Experimental
public final class AEADAdditional {

    private final byte @NotNull [] aad;
}
