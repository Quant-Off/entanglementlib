package space.qu4nt.entanglementlib.security.data;

import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;

@FunctionalInterface
public interface SDCConsumer {

    void accept(SensitiveDataContainer container) throws ELIBSecurityProcessException;
}
