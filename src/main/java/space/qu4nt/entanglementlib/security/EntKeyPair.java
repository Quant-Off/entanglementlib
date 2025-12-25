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

/**
 * {@link KeyPair}를 래핑하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public record EntKeyPair(KeyPair keyPair) {

    /**
     * {@link EntKeyPair} 객체를 생성합니다.
     *
     * @param keyPair 키 쌍
     */
    public EntKeyPair(final @NotNull KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * 키 쌍을 {@link Pair} 객체로 반환하는 메소드입니다.
     *
     * @return {@link PublicKey}와 {@link PrivateKey}를 포함하는 Pair 객체
     */
    public Pair<PublicKey, PrivateKey> asPair() {
        return new Pair<>(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * 키 쌍을 바이트 배열의 {@link Pair} 객체로 반환하는 메소드입니다.
     *
     * @return 인코딩된 {@link PublicKey}와 {@link PrivateKey}를 포함하는 Pair 객체
     */
    public Pair<byte[], byte[]> asBytesPair() {
        return new Pair<>(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
    }

}
