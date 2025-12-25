/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.util.StringUtil;

@Getter
public enum Mode {

    /**
     * Mode: Electronic Codebook
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

    private final String name = (name().startsWith("AEAD_")) ? name().replace("AEAD_", "") : name();

    public static String getFullName(final @NotNull String algorithmName, final @NotNull Mode mode, final @NotNull Padding padding, @Nullable Digest digest) {
        if (digest == null) {
            return String.format("%s/%s/%s", algorithmName, mode.name, padding.getName());
        }
        // AEAD
        if (algorithmName.equals("AES") || algorithmName.equals("ChaCha20")) {
            String fullPaddingName = StringUtil.replace(padding.getName(), "{digest}", digest.getName());
            return String.format("%s/%s/%s", algorithmName, mode.name, fullPaddingName);
        }
        throw new IllegalArgumentException(algorithmName + " algorithm does not support AEAD!");
    }

    public static String getFullName(final @NotNull String algorithmName, final @NotNull Mode mode, final @NotNull Padding padding) {
        return getFullName(algorithmName, mode, padding, null);
    }

}
