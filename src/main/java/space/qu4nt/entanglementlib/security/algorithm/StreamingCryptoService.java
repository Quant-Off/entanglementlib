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
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 스트리밍 방식의 대칭키 암호화 서비스를 정의하는 인터페이스입니다.
 * <p>
 * 이 인터페이스는 대용량 데이터를 처리하기 위해 {@link ByteBuffer} 입출력 객체를
 * 사용하여 데이터를 암호화하거나 복호화하는 기능을 제공합니다.
 * <p>
 * {@link SymmetricCryptoService}가 메모리 내의 바이트 배열 처리에 중점을 둔다면,
 * 이 서비스는 메모리 사용량을 최소화하면서 지속적인 데이터 흐름(파일, 네트워크 등)을 처리하는 데 적합합니다.
 *
 * @author Q. T. Felix
 * @see SymmetricCryptoService
 * @since 1.0.0
 */
public interface StreamingCryptoService extends KeyService {

    Path getEncryptedOutput();

    Path getDecryptedOutput();

    /**
     * 입력 스트림에서 평문 데이터를 읽어 암호화한 후 출력 스트림에 기록하는 메소드입니다.
     * <p>
     * 이 메소드는 스트림을 닫지 않으므로, 호출자가 스트림 리소스를 관리해야 합니다.
     *
     * @param secretKey    암호화에 사용할 대칭 키
     * @param inputBuffer  평문 데이터를 읽을 입력 버퍼
     * @param outputBuffer 암호문을 기록할 출력 버퍼
     * @throws InvalidKeyException               잘못된 키가 제공된 경우
     * @throws NoSuchAlgorithmException          지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException           지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibSecureIllegalStateException 서비스가 이미 닫힌 경우
     */
    int encryptStream(@NotNull SecretKey secretKey,
                      @NotNull ByteBuffer inputBuffer,
                      @NotNull ByteBuffer outputBuffer)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, ShortBufferException;

    /**
     * 입력 스트림에서 암호문 데이터를 읽어 복호화한 후 출력 스트림에 기록하는 메소드입니다.
     * <p>
     * 이 메소드는 스트림을 닫지 않으므로, 호출자가 스트림 리소스를 관리해야 합니다.
     *
     * @param secretKey    복호화에 사용할 대칭 키
     * @param inputBuffer  암호문을 읽을 입력 스트림
     * @param outputBuffer 복호화된 평문을 기록할 출력 스트림
     * @throws InvalidKeyException               잘못된 키가 제공된 경우
     * @throws NoSuchAlgorithmException          지정된 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException           지정된 프로바이더를 사용할 수 없는 경우
     * @throws EntLibSecureIllegalStateException 서비스가 이미 닫힌 경우
     */
    int decryptStream(@NotNull SecretKey secretKey,
                      @NotNull ByteBuffer inputBuffer,
                      @NotNull ByteBuffer outputBuffer)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException;
}