/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail.ChaCha20Poly1305SymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.AEADCipherStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.StreamCipherStrategy;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;
import space.qu4nt.entanglementlib.util.io.EntFile;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.function.BiConsumer;

/**
 * ChaCha20-Poly1305 AEAD 암호화 전략 클래스입니다.
 * <p>
 * ChaCha20은 AES의 대안으로 사용되는 고속 스트림 암호이고,
 * Poly1305는 고속 메시지 인증 코드(MAC) 알고리즘입니다.
 * ChaCha20-Poly1305는 이 두 알고리즘을 결합한 AEAD(Authenticated Encryption with Associated Data)
 * 암호화 방식으로, 기밀성과 무결성을 동시에 보장합니다.
 * </p>
 * <p>
 * 스트림 암호화는 {@link EntFile#byteBufferStreaming(Path, Path, int, int, BiConsumer)}
 * 메소드를 사용하여 대용량 파일을 청크 단위로 처리할 수 있습니다.
 * IV(Nonce) 길이는 12바이트(96비트)로 고정되어 있으며, MAC 크기는 16바이트(128비트)입니다.
 * </p>
 * <p>
 * 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see StreamCipherStrategy
 * @see AEADCipherStrategy
 * @see CipherType#CHACHA20_POLY1305
 */
@Slf4j
public final class ChaCha20Poly1305Strategy implements StreamCipherStrategy, AEADCipherStrategy {

    /**
     * 청크 처리 크기 (64KB)입니다.
     */
    private static final int CHUNK_SIZE = 64 * 1024; // 64KB

    /**
     * MAC 크기 (128비트, 16바이트)입니다.
     */
    private static final int MAC_SIZE = 16; // 128 bits

    /**
     * Nonce(IV) 크기 (96비트, 12바이트)입니다.
     */
    private static final int NONCE_SIZE = 12; // 96 bits

    /**
     * AAD(Additional Authenticated Data) 데이터입니다.
     */
    private byte @Nullable [] aad;
    // Thread-safe하지 않은 엔진이므로 각 호출마다 새로 생성하거나 ThreadLocal 사용 고려
    // 여기서는 간단히 매번 생성하거나 로컬 변수로 사용하도록 구조 변경

    /**
     * ChaCha20Poly1305Strategy 생성자입니다.
     */
    ChaCha20Poly1305Strategy() {
    }

    /**
     * AAD(Additional Authenticated Data)를 설정하는 메소드입니다.
     * <p>
     * AAD는 암호화되지 않지만 무결성이 보장됩니다.
     * 암호화/복호화 수행 전에 호출되어야 합니다.
     * </p>
     *
     * @param aad 추가 인증 데이터
     * @return 메소드 체이닝을 위한 {@code this}
     */
    @Override
    public AEADCipherStrategy updateAAD(byte @NotNull [] aad) {
        if (aad != null) {
            this.aad = Arrays.copyOf(aad, aad.length);
            // 전달받은 aad 원본은 호출자가 관리하거나 필요시 소거한다고 가정 (여기서는 복사본을 저장)
        } else {
            this.aad = null;
        }
        return this;
    }

    /**
     * 입력 버퍼의 데이터를 스트리밍 방식으로 암호화하여 출력 버퍼에 쓰는 메소드입니다.
     * <p>
     * 청크 단위(64KB)로 데이터를 처리하며, 각 청크마다 독립적인 IV(Nonce)가 생성됩니다.
     * 출력 형식은 각 청크당 {@code IV(12바이트) + CipherText + MAC(16바이트)}입니다.
     * </p>
     *
     * @param key          암호화에 사용할 키
     * @param inputBuffer  암호화할 데이터가 담긴 입력 버퍼
     * @param outputBuffer 암호화된 데이터를 쓸 출력 버퍼
     * @return 처리된 바이트 수
     * @throws IllegalArgumentException 출력 버퍼가 너무 작은 경우
     * @throws RuntimeException         키가 {@code null}인 경우
     */
    @Override
    public int streamEncrypt(@NotNull EntLibCryptoKey key, @NotNull ByteBuffer inputBuffer, @NotNull ByteBuffer outputBuffer) {
        // 스트림 암호화 시 청크 단위로 처리
        // 각 청크는 독립적인 IV(Nonce)를 가져야 안전함 (또는 카운터 증가 방식)
        // 여기서는 단순화를 위해 전체 데이터를 읽어서 처리하는 기존 방식 대신,
        // ByteBuffer에서 읽어온 데이터를 청크 단위로 암호화하여 출력 버퍼에 씀

        // 주의: 이 메소드는 단일 호출로 간주되므로, 내부적으로 청크 처리를 수행함.
        // 입력 버퍼의 모든 데이터를 읽어서 암호화.

        byte[] input = new byte[inputBuffer.remaining()];
        inputBuffer.get(input);

        // 결과 크기 예측: (청크 개수 * (IV + MAC)) + 원본 크기
        int chunkCount = (input.length + CHUNK_SIZE - 1) / CHUNK_SIZE;
        int overheadPerChunk = NONCE_SIZE + MAC_SIZE;
        int estimatedOutputSize = input.length + (chunkCount * overheadPerChunk);

        if (outputBuffer.remaining() < estimatedOutputSize) {
            throw new IllegalArgumentException("Output buffer is too small. Required: " + estimatedOutputSize);
        }

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte[] keyBytes = key.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        KeyParameter keyParam = new KeyParameter(keyBytes);

        try {
            ByteArrayChunkProcessor.processInChunks(input, CHUNK_SIZE, (data, offset, length) -> {
                // 각 청크마다 고유한 IV 생성
                byte[] iv = EntLibKey.generateSafeRandomBytes(NONCE_SIZE);
                AEADParameters params = new AEADParameters(keyParam, MAC_SIZE * 8, iv, aad);

                ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
                cipher.init(true, params);

                byte[] chunkOutput = new byte[cipher.getOutputSize(length)];
                int len = cipher.processBytes(data, offset, length, chunkOutput, 0);
                len += cipher.doFinal(chunkOutput, len);

                // 출력: IV + EncryptedChunk(MAC 포함)
                outputBuffer.put(iv);
                outputBuffer.put(chunkOutput, 0, len);
            });
        } finally {
            KeyDestroyHelper.zeroing(keyBytes);
        }

        return estimatedOutputSize; // 실제 쓰여진 바이트 수와 다를 수 있으나, put으로 위치가 이동됨.
    }

    /**
     * 입력 버퍼의 데이터를 스트리밍 방식으로 복호화하여 출력 버퍼에 쓰는 메소드입니다.
     * <p>
     * 암호화된 청크 구조({@code IV + CipherText + MAC})를 인식하여 처리합니다.
     * 각 청크의 MAC을 검증하여 무결성을 확인합니다.
     * </p>
     *
     * @param key          복호화에 사용할 키
     * @param inputBuffer  복호화할 데이터가 담긴 입력 버퍼
     * @param outputBuffer 복호화된 데이터를 쓸 출력 버퍼
     * @return 복호화된 총 바이트 수
     * @throws IllegalStateException MAC 검증 실패 시
     * @throws RuntimeException      키가 {@code null}인 경우
     */
    @Override
    public int streamDecrypt(@NotNull EntLibCryptoKey key, @NotNull ByteBuffer inputBuffer, @NotNull ByteBuffer outputBuffer) {
        // 복호화는 암호화된 청크 구조(IV + CipherText + MAC)를 인식해야 함.
        // 암호화 시 CHUNK_SIZE 단위로 평문을 잘랐지만, 암호문 청크 크기는 CHUNK_SIZE + NONCE_SIZE + MAC_SIZE 임.
        // 마지막 청크는 더 작을 수 있음.

        // 스트림 복호화는 구조상 복잡함. 입력 버퍼가 전체 데이터를 포함한다고 가정하고 처리.
        // 만약 입력 버퍼가 부분 데이터라면 상태 관리가 필요하지만, 현재 인터페이스는 상태를 유지하지 않음.

        byte[] input = new byte[inputBuffer.remaining()];
        inputBuffer.get(input);

        byte[] keyBytes = key.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        KeyParameter keyParam = new KeyParameter(keyBytes);

        int readOffset = 0;
        int totalDecrypted = 0;

        try {
            while (readOffset < input.length) {
                // 1. IV 읽기
                if (readOffset + NONCE_SIZE > input.length) break; // 데이터 부족
                byte[] iv = Arrays.copyOfRange(input, readOffset, readOffset + NONCE_SIZE);
                readOffset += NONCE_SIZE;

                // 2. 청크 데이터 길이 계산
                // 암호화 시 평문 CHUNK_SIZE -> 암호문 CHUNK_SIZE + MAC_SIZE
                // 마지막 청크일 수 있으므로 남은 길이 확인
                int remaining = input.length - readOffset;
                int currentCipherChunkSize = Math.min(remaining, CHUNK_SIZE + MAC_SIZE);

                if (currentCipherChunkSize < MAC_SIZE) break; // 최소 MAC 크기보다 작으면 오류

                AEADParameters params = new AEADParameters(keyParam, MAC_SIZE * 8, iv, aad);
                ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
                cipher.init(false, params);

                byte[] chunkOutput = new byte[cipher.getOutputSize(currentCipherChunkSize)];
                int len = cipher.processBytes(input, readOffset, currentCipherChunkSize, chunkOutput, 0);
                len += cipher.doFinal(chunkOutput, len);

                outputBuffer.put(chunkOutput, 0, len);
                totalDecrypted += len;

                readOffset += currentCipherChunkSize;
            }
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Decryption failed", e);
        } finally {
            KeyDestroyHelper.zeroing(keyBytes);
        }

        return totalDecrypted;
    }

    /**
     * 평문을 ChaCha20-Poly1305 알고리즘으로 암호화하는 메소드입니다.
     * <p>
     * 12바이트의 Nonce(IV)가 자동으로 생성되며,
     * 결과는 {@code IV(12바이트) + CipherText + MAC(16바이트)} 형식으로 반환됩니다.
     * AAD가 설정된 경우 함께 인증에 사용됩니다.
     * </p>
     *
     * @param key        암호화에 사용할 키
     * @param plainBytes 암호화할 평문 바이트 배열
     * @return 암호화된 바이트 배열 (IV + CipherText + MAC)
     * @throws IllegalStateException 암호화 실패 시
     * @throws RuntimeException      키가 {@code null}인 경우
     */
    @Override
    public byte @NotNull [] encrypt(@NotNull EntLibCryptoKey key, byte[] plainBytes) {
        byte[] iv = EntLibKey.generateSafeRandomBytes(NONCE_SIZE);
        byte[] keyBytes = key.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        KeyParameter keyParam = new KeyParameter(keyBytes);
        AEADParameters params = new AEADParameters(keyParam, MAC_SIZE * 8, iv, aad);
        KeyDestroyHelper.zeroing(keyBytes);

        try {
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            cipher.init(true, params);

            byte[] output = new byte[cipher.getOutputSize(plainBytes.length)];
            int len = cipher.processBytes(plainBytes, 0, plainBytes.length, output, 0);
            len += cipher.doFinal(output, len);

            byte[] result = new byte[iv.length + len];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(output, 0, result, iv.length, len);

            return result;
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 암호문을 ChaCha20-Poly1305 알고리즘으로 복호화하는 메소드입니다.
     * <p>
     * 입력된 암호문에서 12바이트의 IV를 추출하고 MAC을 검증하여 복호화를 수행합니다.
     * AAD가 설정된 경우 함께 인증에 사용됩니다.
     * </p>
     *
     * @param key        복호화에 사용할 키
     * @param ciphertext 복호화할 암호문 바이트 배열 (IV + CipherText + MAC)
     * @return 복호화된 평문 바이트 배열
     * @throws IllegalArgumentException 암호문이 너무 짧은 경우
     * @throws IllegalStateException    MAC 검증 실패 시
     * @throws RuntimeException         키가 {@code null}인 경우
     */
    @Override
    public byte @NotNull [] decrypt(@NotNull EntLibCryptoKey key, byte[] ciphertext) {
        if (ciphertext.length < NONCE_SIZE + MAC_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        byte[] iv = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
        byte[] actualCiphertext = Arrays.copyOfRange(ciphertext, NONCE_SIZE, ciphertext.length);

        byte[] keyBytes = key.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");
        KeyParameter keyParam = new KeyParameter(keyBytes);
        AEADParameters params = new AEADParameters(keyParam, MAC_SIZE * 8, iv, aad);
        KeyDestroyHelper.zeroing(keyBytes);

        try {
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            cipher.init(false, params);

            byte[] output = new byte[cipher.getOutputSize(actualCiphertext.length)];
            int len = cipher.processBytes(actualCiphertext, 0, actualCiphertext.length, output, 0);
            len += cipher.doFinal(output, len);

            return Arrays.copyOf(output, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름 "ChaCha20-Poly1305"
     */
    @Override
    public String getAlgorithmName() {
        return "ChaCha20-Poly1305";
    }

    /**
     * 이 스트레티지의 알고리즘 타입을 반환하는 메소드입니다.
     *
     * @return {@link CipherType#CHACHA20_POLY1305}
     */
    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return CipherType.CHACHA20_POLY1305;
    }

    // 테스트용 psvm
    public static void main(String[] args) {
        byte[] plain = "Hello, ChaCha20-Poly1305 Secure World!".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305Strategy chaCha20Poly1305Strategy = new ChaCha20Poly1305Strategy();

        // AAD 설정
        chaCha20Poly1305Strategy.updateAAD("Test AAD Data".getBytes(StandardCharsets.UTF_8));

        ChaCha20Poly1305SymmetricKeyStrategy keyStrategy = ChaCha20Poly1305SymmetricKeyStrategy.create(chaCha20Poly1305Strategy);

        try (EntLibCryptoKey key = keyStrategy.generateKey()) {
            // 키 확인 (테스트용 - 실제 운영 환경에서는 키를 로그에 찍으면 안 됨)
            MemorySegment keySegment = key.getKeySegment();
            byte[] keyBytes = keySegment.toArray(ValueLayout.JAVA_BYTE);
            log.info("Key (Hex): {}", Hex.toHexString(keyBytes));
            KeyDestroyHelper.zeroing(keyBytes); // 확인 후 즉시 소거
            {
                // 암호화
                byte[] encrypted = chaCha20Poly1305Strategy.encrypt(key, plain);
                log.info("Normal Encrypted: {}", Hex.toHexString(encrypted));

                // 복호화
                byte[] decrypted = chaCha20Poly1305Strategy.decrypt(key, encrypted);
                log.info("Normal Decrypted: {}", Hex.toHexString(decrypted));
                log.info("Normal Decrypted Plain: {}", new String(decrypted, StandardCharsets.UTF_8));
            } // Normal Cipher

            {
                Path input = Path.of(InternalFactory.envEntanglementPublicDir(), "CHACHATestInput.json");
                Path output = Path.of(InternalFactory.envEntanglementPublicDir(), "CHACHAP1305TestOutput.json");
                Path decOutput = Path.of(InternalFactory.envEntanglementPublicDir(), "CHACHAP1305TestDecrypted.json");

                // 1. 스트림 암호화
                // 평문 1024바이트를 읽어 IV(12) + MAC(16)이 추가된 1052바이트를 출력합니다.
                int plainSize = 1024;
                int cipherSize = plainSize + 12 + 16; // 1052

                EntFile.byteBufferStreaming(input, output, plainSize, cipherSize, (i, o) ->
                        chaCha20Poly1305Strategy.streamEncrypt(key, i, o));

                // 2. 스트림 복호화 (중요)
                // 파일에서 암호화된 패킷 단위(1052바이트)를 통째로 읽어와야 MAC 검증이 가능합니다.
                EntFile.byteBufferStreaming(output, decOutput, cipherSize, plainSize, (i, o) ->
                        chaCha20Poly1305Strategy.streamDecrypt(key, i, o));
            } // Stream Cipher
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
