package space.qu4nt.entanglementlib.annotations;

import java.lang.annotation.Documented;

@Documented
public @interface Only {

    String value() default "";
}
