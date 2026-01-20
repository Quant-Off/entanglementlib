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

package space.qu4nt.entanglementlib.security.algorithm;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.security.EntLibKey.CustomWiper;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;

import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 키 생성 서비스를 제공하는 인터페이스입니다.
 * <p>
 * {@link KeyPair} 객체와 {@link SecretKey} 객체는 키의 성격에 따라
 * 생성될 수 있습니다. 쉽게 말해, 만들어질 키의 암호화 방식이 대칭인지 비대칭인지에
 * 따라 달라집니다.
 * <p>
 * {@code KeyPair}는 비대칭키({@code Asymmetric}) 암호화 알고리즘이 사용할
 * 수 있고, {@code SecretKey}는 대칭키({@code Symmetric}) 암호화 알고리즘이
 * 사용할 수 있습니다.
 * <p>
 * 대칭키 객체는 통신의 맥락에서 통신 당사자만 보유하고 있어야 하지만, 비대칭키 객체는
 * 공개 키는 누구나, 개인 키는 소유자만이 가질 수 있습니다.
 * <p>
 * 이 서비스는 기본적으로 구현체가 비대칭키 암호화 알고리즘을 사용할 것이라 예상합니다.
 * 따라서 {@link #generateSecretKey(CustomWiper)} 메소드는 기본 구현으로
 * {@link EntLibAlgorithmSettingException} 예외를 던지도록 설계되어 있습니다.
 * <p>
 * 만약 구현체가 대칭키 암호화 알고리즘을 사용한다면 해당 메소드를 재정의해주어야 합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public interface KeyService {

    /**
     * 비대칭키 페어를 생성하는 메소드입니다.
     *
     * @param callback 키 소거 완료 후 수행될 콜백 {@link CustomWiper}
     * @return 생성된 키 페어를 래핑하는 {@link EntLibKeyPair} 객체
     * @throws InvalidAlgorithmParameterException 지정된 알고리즘 매개변수가 유효하지 않은 경우
     * @throws NoSuchAlgorithmException           지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException            지정된 프로바이더를 사용할 수 없는 경우
     */
    @NotNull
    EntLibKeyPair generateEntKeyPair(@Nullable CustomWiper<KeyPair> callback) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * 대칭키를 생성하는 메소드입니다.
     * 특정 알고리즘에서 지원되지 않을 수 있으며, 이 경우 {@link EntLibAlgorithmSettingException}
     * 예외가 발생합니다.
     *
      @param callback 키 소거 완료 후 수행될 콜백 {@link CustomWiper}
     * @return 생성된 대칭키를 래핑하는 {@link SecretKey} 객체
     * @throws NoSuchAlgorithmException        지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException         지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibAlgorithmSettingException 해당 알고리즘에서 지원되지 않는 형식일 경우
     */
    @NotNull
    default EntLibSecretKey generateSecretKey(@Nullable CustomWiper<SecretKey> callback) throws NoSuchAlgorithmException, NoSuchProviderException {
        throw new EntLibAlgorithmSettingException(KeyService.class, "not-support-secret-key-exc");
    }
}
