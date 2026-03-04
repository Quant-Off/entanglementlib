package space.qu4nt.entanglementlib.core.exception.security.checked;

import java.io.Serial;

public class ELIBSecurityException extends Exception {

    @Serial
    private static final long serialVersionUID = 7009027800432974319L;

    public ELIBSecurityException() {
    }

    public ELIBSecurityException(String message) {
        super(message);
    }

    public ELIBSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityException(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
