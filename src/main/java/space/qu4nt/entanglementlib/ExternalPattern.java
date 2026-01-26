/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/**
 * 반드시 외부에서만 사용됨을 알리는 마커 어노테이션입니다.
 * {@link InternalFactory} 객체 부트스트랩 시, 내부(internal)에서 사용되는 멤버와
 * 외부(external)에서 사용되는 멤버는 다르다는 것을 명확히 하기 위해 사용됩니다.
 * <p>
 * 이 어노테이션은 타입 레벨에 사용하지 마세요. 혼동이 생길 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Target(ElementType.TYPE_USE)
public @interface ExternalPattern {

}
