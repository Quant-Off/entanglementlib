package space.qu4nt.entanglementlib.core.exception.security.critical;

import java.io.Serial;

public class ELIBSecurityNativeCritical extends ELIBSecurityCritical {

    @Serial
    private static final long serialVersionUID = -7557337159377165891L;

    public ELIBSecurityNativeCritical() {
    }

    public ELIBSecurityNativeCritical(String message) {
        super(message);
    }

    public ELIBSecurityNativeCritical(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityNativeCritical(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityNativeCritical(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
