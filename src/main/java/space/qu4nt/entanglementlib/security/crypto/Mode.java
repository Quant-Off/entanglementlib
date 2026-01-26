/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.security.crypto.strategy.EntLibCryptoStrategy;
import space.qu4nt.entanglementlib.util.StringUtil;

@Getter
public enum Mode {

    /**
     * Mode: Electronic Codebook
     * <p>
     * 얽힘 라이브러리에선 보안상 권장하지 않는 모드입니다.
     */
    ECB,
    /**
     * Mode: Cipher Block Chaining
     */
    CBC,
    /**
     * Mode: Cipher Feedback
     */
    CFB,
    /**
     * Mode: Output Feedback
     */
    OFB,
    /**
     * Mode: Counter
     */
    CTR,

    /**
     * Mode: Galois/Counter
     */
    AEAD_GCM,
    /**
     * Mode: Counter with CBC-MAC
     */
    AEAD_CCM;

    private final boolean aead = name().startsWith("AEAD_");
    private final String name = aead ? name().replace("AEAD_", "") : name();

    public static String getFullName(final @NotNull String algorithmName, final @NotNull Mode mode, final @NotNull Padding padding, @Nullable Digest digest)
            throws EntLibSecureIllegalArgumentException {
        if (digest == null) {
            return String.format("%s/%s/%s", algorithmName, mode.name, padding.getName());
        }
        // AEAD
        if (algorithmName.equalsIgnoreCase("AES") || algorithmName.equalsIgnoreCase("ChaCha20")) {
            String fullPaddingName = StringUtil.replace(padding.getName(), "{digest}", digest.getName());
            return String.format("%s/%s/%s", algorithmName, mode.name, fullPaddingName);
        }
        throw new EntLibSecureIllegalArgumentException(EntLibCryptoStrategy.class, "alg-not-support-aead-exc", null, algorithmName);
    }

    public static String getFullName(final @NotNull String algorithmName, final @NotNull Mode mode, final @NotNull Padding padding)
            throws EntLibSecureIllegalArgumentException {
        return getFullName(algorithmName, mode, padding, null);
    }

}