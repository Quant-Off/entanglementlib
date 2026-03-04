package space.qu4nt.entanglementlib.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/// 보안적 책임은 호출자에게 있음을 알리는 어노테이션입니다. 호출자가 해당 어노테이션이
/// 사용된 멤버 사용 시, 작업 종료 후 반드시 보안 작업이 필요함을 의미합니다.
///
/// 예를 들어, 이 어노테이션이 (복사본이 아닌) 원본 데이터를 반환하는 메소드에 사용되었고
/// 해당 메소드를 사용하고자 하는 경우, 반환받은 데이터를 소거해야 함을 의미합니다.
///
/// 또는 이 어노테이션이 사용된 멤버는 네이티브 측의 "호출자 할당" 패턴을 사용한 경우로,
/// 작업이 종료됨과 동시에 네이티브에 할당 해제 함수를 호출해야 함을 의미합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
@Documented
@Target(ElementType.TYPE_USE)
public @interface CallerResponsibility {

    /**
     * 책임 전가의 사유 또는 설명를 정의합니다.
     *
     * @return 책임 전가 사유 또는 설명
     */
    String value() default "";

}