package space.qu4nt.entanglementlib.security.entlibnative;

import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;

@FunctionalInterface
public interface HandleProcessConsumer<T> {

    void accept(T t) throws Throwable;
}
