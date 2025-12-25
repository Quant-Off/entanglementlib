/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public record EntKeyPair(KeyPair keyPair) {

    public EntKeyPair(final @NotNull KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public Pair<PublicKey, PrivateKey> asPair() {
        return new Pair<>(keyPair.getPublic(), keyPair.getPrivate());
    }

    public Pair<byte[], byte[]> asBytesPair() {
        return new Pair<>(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
    }

}
