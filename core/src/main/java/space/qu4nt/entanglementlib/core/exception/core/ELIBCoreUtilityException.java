package space.qu4nt.entanglementlib.core.exception.core;

import java.io.Serial;

public class ELIBCoreUtilityException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -3902892852757530511L;

    public ELIBCoreUtilityException() {
    }

    public ELIBCoreUtilityException(String message) {
        super(message);
    }

    public ELIBCoreUtilityException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBCoreUtilityException(Throwable cause) {
        super(cause);
    }

    public ELIBCoreUtilityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
