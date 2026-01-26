/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.critical;

import java.io.Serial;

public class EntLibEnvError extends EntLibError {

    @Serial
    private static final long serialVersionUID = -4680763736515724771L;

    public EntLibEnvError(String envName) {
        super(envName + " env variables are missing");
    }
}
