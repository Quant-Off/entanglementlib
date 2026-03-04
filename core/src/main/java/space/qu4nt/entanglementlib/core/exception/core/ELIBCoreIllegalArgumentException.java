package space.qu4nt.entanglementlib.core.exception.core;

import java.io.Serial;

public class ELIBCoreIllegalArgumentException extends ELIBCoreException {

    @Serial
    private static final long serialVersionUID = 8726329909869726228L;

    public ELIBCoreIllegalArgumentException() {
    }

    public ELIBCoreIllegalArgumentException(String message) {
        super(message);
    }

    public ELIBCoreIllegalArgumentException(String message, Throwable cause) {
        super(message, cause);
    }

    public ELIBCoreIllegalArgumentException(Throwable cause) {
        super(cause);
    }

    public ELIBCoreIllegalArgumentException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
