package space.qu4nt.entanglementlib.core.exception.security.checked;

import java.io.Serial;

public class ELIBSecurityIllegalStateException extends ELIBSecurityException {

    @Serial
    private static final long serialVersionUID = -2918719188402645982L;

    public ELIBSecurityIllegalStateException() {
    }

    public ELIBSecurityIllegalStateException(String message) {
        super(message);
    }

    public ELIBSecurityIllegalStateException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityIllegalStateException(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityIllegalStateException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
