package space.qu4nt.entanglementlib.core.exception.security.checked;

import java.io.Serial;

public class ELIBSecurityUnsafeUsageException extends ELIBSecurityException {

    @Serial
    private static final long serialVersionUID = 1672793311305065673L;

    public ELIBSecurityUnsafeUsageException() {
    }

    public ELIBSecurityUnsafeUsageException(String message) {
        super(message);
    }

    public ELIBSecurityUnsafeUsageException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityUnsafeUsageException(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityUnsafeUsageException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
