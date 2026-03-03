package space.qu4nt.entanglementlib.core.exception.security.checked;

import java.io.Serial;

public class ELIBSecurityIOException extends ELIBSecurityException {

    @Serial
    private static final long serialVersionUID = -5611460691131894020L;

    public ELIBSecurityIOException() {
    }

    public ELIBSecurityIOException(String message) {
        super(message);
    }

    public ELIBSecurityIOException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBSecurityIOException(Throwable cause) {
        super(cause);
    }

    public ELIBSecurityIOException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
