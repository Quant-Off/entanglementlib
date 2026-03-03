package space.qu4nt.entanglementlib.core.exception.security.critical;

import java.io.Serial;

public class ELIBSecurityCritical extends Error {

    @Serial
    private static final long serialVersionUID = -6905370663633314089L;

    public ELIBSecurityCritical() {
    }

    public ELIBSecurityCritical(String message) {
        super(message);
    }

    public ELIBSecurityCritical(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityCritical(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityCritical(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
