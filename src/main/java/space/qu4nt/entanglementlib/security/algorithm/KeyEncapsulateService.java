/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyEncapsulateService extends EntLibCryptoService, KeyService {

    Pair<byte[], SecretKey> encapsulate(@NotNull PublicKey pk) throws GeneralSecurityException;

    byte[] decapsulate(@NotNull SecretKey secretKey, @NotNull PrivateKey sk, byte @NotNull [] ciphertext)
            throws GeneralSecurityException;
}
