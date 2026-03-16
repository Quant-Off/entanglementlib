package space.qu4nt.entanglementlib.security.entlibnative;

public record FFIStructEntLibResult<A>(byte typeId, byte status, A data) {
}
