package space.qu4nt.entanglementlib.core.exception.core;

import java.io.Serial;

public class ELIBCoreException extends Exception {

    @Serial
    private static final long serialVersionUID = -8478889423877054012L;

    public ELIBCoreException() {
    }

    public ELIBCoreException(String message) {
        super(message);
    }

    public ELIBCoreException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBCoreException(Throwable cause) {
        super(cause);
    }

    public ELIBCoreException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
