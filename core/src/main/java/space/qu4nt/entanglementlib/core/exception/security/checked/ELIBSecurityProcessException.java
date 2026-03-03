package space.qu4nt.entanglementlib.core.exception.security.checked;

import java.io.Serial;

public class ELIBSecurityProcessException extends ELIBSecurityException {

    @Serial
    private static final long serialVersionUID = -4547118937218025817L;

    public ELIBSecurityProcessException() {
    }

    public ELIBSecurityProcessException(String message) {
        super(message);
    }

    public ELIBSecurityProcessException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityProcessException(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityProcessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
