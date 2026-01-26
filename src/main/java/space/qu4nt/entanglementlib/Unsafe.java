/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import com.quant.quantregular.annotations.QuantTypeOwner;
import com.quant.quantregular.annotations.Quanters;

/// # Basically Unsafe Usage
///
/// #### 사용에 주의하세요!
///
/// 이 어노테이션이 사용된 요소(멤버)가 본질적으로 안전하지 않으며 보안 위험을 초래할 수 있음을 나타내기 위한
/// 어노테이션입니다.
/// 
/// 구체적으로 이 어노테이션은 사용된 메소드, 필드 또는 타입 등의 멤버가 다음 이유 중 하나로 인해 안전하지
/// 않음을 나타냅니다.
///
/// - 표준 안전 검사나 캡슐화 메커니즘을 우회하는 코드
/// - 기본 작동 방식(세부 로직, 알고리즘 자체 및 불건전 참조 등) 자체에 문제
/// - 보안 취약점 발견
///
/// 이 API를 사용하려면 기본 구현 및 잠재적인 부작용에 대한 깊은 이해가 필요합니다.
/// 
/// # Important
///
/// 이 요소를 부적절하게 사용하면 `메모리 손상`, `데이터 유출` 또는 **임의 코드 실행을 포함하되 이에 국한되지 않는
/// 심각한 보안 취약점이 발생**할 수 있습니다. 또한 정의되지 않은 동작이나 애플리케이션 불안정을 초래할 수도 있습니다.
/// 
/// 사용자는 절대적으로 필요한 경우에만 이 요소를 사용해야 하며, 위험을 완화하기 위해 적절한 보안 조치와
/// 검증 로직이 마련되어 있는지 확인해야 합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
@QuantTypeOwner(Quanters.Q_T_FELIX)
public @interface Unsafe {
}
