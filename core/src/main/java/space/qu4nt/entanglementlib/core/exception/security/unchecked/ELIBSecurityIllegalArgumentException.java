package space.qu4nt.entanglementlib.core.exception.security.unchecked;

import java.io.Serial;

public class ELIBSecurityIllegalArgumentException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 3401738922121497475L;

    public ELIBSecurityIllegalArgumentException() {
    }

    public ELIBSecurityIllegalArgumentException(String message) {
        super(message);
    }

    public ELIBSecurityIllegalArgumentException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityIllegalArgumentException(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityIllegalArgumentException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
