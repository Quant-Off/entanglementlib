/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.security;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPrivateKey;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.security.EntLibKeyDestroyException;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * {@link KeyPair}를 래핑하여 추가적인 유틸리티 기능과 안전한 파기(Wiping) 메커니즘을 제공하는 클래스입니다.
 * <p>
 * 이 클래스는 Java의 표준 {@link KeyPair}를 캡슐화하며, Bouncy Castle 라이브러리와의 상호 운용성을 지원합니다.
 * 또한, PQC(Post-Quantum Cryptography) 키와 같은 민감한 키 데이터를 메모리에서 안전하게 소거하는 기능을 포함합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public record EntLibKeyPair(KeyPair keyPair) implements EntLibKey<KeyPair> {

    /**
     * 키 쌍에 포함된 개인 키 데이터를 메모리에서 안전하게 소거(Wipe)하는 메소드입니다.
     * <p>
     * 지원되는 BouncyCastle PQC 개인 키(ML-DSA, ML-KEM, SLH-DSA)의 경우, 리플렉션을 통해 내부 파라미터에 접근하여 데이터를 파기합니다.
     * 그 외의 경우 또는 추가적인 파기 로직이 필요한 경우, 제공된 콜백을 통해 사용자 정의 파기 로직을 수행할 수 있습니다.
     *
     * @param callback 키 파기 후 추가적으로 수행할 사용자 정의 콜백 ({@code null} 허용 안 됨, {@link CustomWiper})
     * @throws EntLibKeyDestroyException 키 파기 중 오류가 발생한 경우
     */
    @Override
    public void wipe(@Nullable CustomWiper<KeyPair> callback) {
        if (keyPair == null) return;
        try {
            if (keyPair.getPrivate() instanceof BCMLDSAPrivateKey bcMldsaSK) {
                // "params"
                Field params = bcMldsaSK.getClass().getDeclaredField("params");
                params.setAccessible(true);
                KeyDestroyHelper.destroy(params.get(bcMldsaSK));
            } else if (keyPair.getPrivate() instanceof BCMLKEMPrivateKey bcMlkemSK) {
                // "params"
                Field params = bcMlkemSK.getClass().getDeclaredField("params");
                params.setAccessible(true);
                KeyDestroyHelper.destroy(params.get(bcMlkemSK));
            } else if (keyPair.getPrivate() instanceof BCSLHDSAPrivateKey bcSlhdsaSK) {
                // "params"
                Field params = bcSlhdsaSK.getClass().getDeclaredField("params");
                params.setAccessible(true);
                KeyDestroyHelper.destroy(params.get(bcSlhdsaSK));
            }
            if (callback != null)
                callback.accept(keyPair);
        } catch (Exception e) {
            throw new EntLibKeyDestroyException(e);
        }

    }

    /**
     * 키 쌍을 BouncyCastle의 {@link AsymmetricKeyParameter} 형식으로 변환하여 {@link Pair}
     * 객체로 반환하는 메소드입니다.
     *
     * @return 공개 키와 개인 키에 해당하는 {@link AsymmetricKeyParameter}를 포함하는 {@link Pair} 객체
     * @throws IOException 키 인코딩 데이터를 읽는 중 오류가 발생한 경우
     */
    public Pair<AsymmetricKeyParameter, AsymmetricKeyParameter> asBCAsymmetricKeyParameterPair() throws IOException {
        return new Pair<>(PublicKeyFactory.createKey(keyPair.getPublic().getEncoded()), PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));
    }

    /**
     * 키 쌍을 {@link PublicKey}와 {@link PrivateKey}의 {@link Pair} 객체로 반환하는 메소드입니다.
     *
     * @return {@link PublicKey}와 {@link PrivateKey}를 포함하는 {@link Pair} 객체
     */
    public Pair<PublicKey, PrivateKey> asPair() {
        return new Pair<>(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * 키 쌍을 인코딩된 바이트 배열의 {@link Pair} 객체로 반환하는 메소드입니다.
     *
     * @return 인코딩된 공개 키와 개인 키 바이트 배열을 포함하는 {@link Pair} 객체
     */
    public Pair<byte[], byte[]> asBytesPair() {
        return new Pair<>(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
    }
}
