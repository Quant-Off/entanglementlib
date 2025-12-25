/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import space.qu4nt.entanglementlib.util.StringUtil;

/**
 * 지원되는 다이제스트 알고리즘을 열거한 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Getter
public enum Digest {

    /**
     * MD5
     */
    MD5,

    /**
     * SHA_1
     */
    SHA_1,

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

    private final String name = StringUtil.replace(name(), "_", "-");

}
