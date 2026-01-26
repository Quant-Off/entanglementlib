/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import lombok.Getter;
import space.qu4nt.entanglementlib.util.StringUtil;

/// 지원되는 다이제스트 알고리즘을 열거한 클래스입니다.
///
/// `SHA3`는 다른 프로덕션에서 호환되지 않을 수 있습니다.
///
/// @author Q. T. Felix
/// @since 1.0.0
@Getter
public enum Digest {

    //
    // Not Recommended - start
    //

    /**
     * MD5
     * @deprecated MD5는 절대 권장되지 않습니다. {@link #SHA_224} 이상의 다이제스트를 사용하세요.
     */
    @Deprecated
    MD5,

    /**
     * SHA_1
     @deprecated SHA_1는 절대 권장되지 않습니다. {@link #SHA_224} 이상의 다이제스트를 사용하세요.
     */
    @Deprecated
    SHA_1,

    //
    // Not Recommended - end
    //

    /**
     * SHA_224
     */
    SHA_224,
    /**
     * SHA_256
     */
    SHA_256,
    /**
     * SHA_384
     */
    SHA_384,
    /**
     * SHA_512
     */
    SHA_512,

    /**
     * SHA3_224
     */
    SHA3_224,
    /**
     * SHA3_256
     */
    SHA3_256,
    /**
     * SHA3_384
     */
    SHA3_384,
    /**
     * SHA3_512
     */
    SHA3_512;

    private final String name = StringUtil.replace(name(), "_", "-").startsWith("SHA-") ?
            StringUtil.replace(name(), "_", "") : StringUtil.replace(name(), "_", "-");
}
