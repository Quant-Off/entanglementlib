/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.util.io.EntFile;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link ChaCha20}, {@link ChaCha20Poly1305} 알고리즘을 사용한
 * 암호화 연산을 테스트하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
class ChaCha20AllTest {

    static final String str4096 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec rhoncus pharetra mi, nec ultrices mi faucibus sed. Quisque volutpat ultrices felis, a scelerisque neque tincidunt vitae. Aliquam hendrerit fermentum risus quis semper. Integer tincidunt ultricies purus, sit amet posuere velit vehicula in. Integer placerat, turpis quis ornare tristique, felis velit euismod lectus, ac varius libero turpis a urna. Quisque cursus, enim quis pellentesque aliquet, mauris erat tempus tortor, ut dictum odio ipsum ac nisl. Vivamus consequat molestie elementum. Vestibulum ornare gravida turpis eu euismod. Mauris id turpis vitae mi rhoncus pulvinar id luctus ex. In tempor, felis vitae vehicula bibendum, odio tellus fringilla orci, id ultrices sapien felis non quam. Pellentesque nec accumsan tellus. Curabitur dictum neque sem, vitae vehicula nunc consequat nec. Proin tristique aliquet dapibus. Sed mauris mauris, mollis eu finibus sed, tristique vel sem. Fusce congue ullamcorper faucibus. Curabitur mattis vel metus eu vivamus.Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec rhoncus pharetra mi, nec ultrices mi faucibus sed. Quisque volutpat ultrices felis, a scelerisque neque tincidunt vitae. Aliquam hendrerit fermentum risus quis semper. Integer tincidunt ultricies purus, sit amet posuere velit vehicula in. Integer placerat, turpis quis ornare tristique, felis velit euismod lectus, ac varius libero turpis a urna. Quisque cursus, enim quis pellentesque aliquet, mauris erat tempus tortor, ut dictum odio ipsum ac nisl. Vivamus consequat molestie elementum. Vestibulum ornare gravida turpis eu euismod. Mauris id turpis vitae mi rhoncus pulvinar id luctus ex. In tempor, felis vitae vehicula bibendum, odio tellus fringilla orci, id ultrices sapien felis non quam. Pellentesque nec accumsan tellus. Curabitur dictum neque sem, vitae vehicula nunc consequat nec. Proin tristique aliquet dapibus. Sed mauris mauris, mollis eu finibus sed, tristique vel sem. Fusce congue ullamcorper faucibus. Curabitur mattis vel metus eu vivamus.Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec rhoncus pharetra mi, nec ultrices mi faucibus sed. Quisque volutpat ultrices felis, a scelerisque neque tincidunt vitae. Aliquam hendrerit fermentum risus quis semper. Integer tincidunt ultricies purus, sit amet posuere velit vehicula in. Integer placerat, turpis quis ornare tristique, felis velit euismod lectus, ac varius libero turpis a urna. Quisque cursus, enim quis pellentesque aliquet, mauris erat tempus tortor, ut dictum odio ipsum ac nisl. Vivamus consequat molestie elementum. Vestibulum ornare gravida turpis eu euismod. Mauris id turpis vitae mi rhoncus pulvinar id luctus ex. In tempor, felis vitae vehicula bibendum, odio tellus fringilla orci, id ultrices sapien felis non quam. Pellentesque nec accumsan tellus. Curabitur dictum neque sem, vitae vehicula nunc consequat nec. Proin tristique aliquet dapibus. Sed mauris mauris, mollis eu finibus sed, tristique vel sem. Fusce congue ullamcorper faucibus. Curabitur mattis vel metus eu vivamus.Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec rhoncus pharetra mi, nec ultrices mi faucibus sed. Quisque volutpat ultrices felis, a scelerisque neque tincidunt vitae. Aliquam hendrerit fermentum risus quis semper. Integer tincidunt ultricies purus, sit amet posuere velit vehicula in. Integer placerat, turpis quis ornare tristique, felis velit euismod lectus, ac varius libero turpis a urna. Quisque cursus, enim quis pellentesque aliquet, mauris erat tempus tortor, ut dictum odio ipsum ac nisl. Vivamus consequat molestie elementum. Vestibulum ornare gravida turpis eu euismod. Mauris id turpis vitae mi rhoncus pulvinar id luctus ex. In tempor, felis vitae vehicula bibendum, odio tellus fringilla orci, id ultrices sapien felis non quam. Pellentesque nec accumsan tellus. Curabitur dictum neque sem, vitae vehicula nunc consequat nec. Proin tristique aliquet dapibus. Sed mauris mauris, mollis eu finibus sed, tristique vel sem. Fusce congue ullamcorper faucibus. Curabitur mattis vel metus eu vivamus.";

    static final Path commonInput = Paths.get(InternalFactory.envEntanglementPublicDir(), "CHACHATestInput.json");
    static final Path chaCha20OutputEnc = commonInput.getParent().resolve("chacha20Encrypted.json");
    static final Path chaCha20OutputDec = commonInput.getParent().resolve("chacha20Decrypted.json");
    static final Path chaCha20Poly1305OutputEnc = commonInput.getParent().resolve("chacha20Poly1305Encrypted.json");
    static final Path chaCha20Poly1305OutputDec = commonInput.getParent().resolve("chacha20Poly1305Decrypted.json");

    static ChaCha20 chaCha20;
    static ChaCha20Poly1305 chaCha20Poly1305;

    static SecretKey chaCha20Key;
    static SecretKey chaCha20Poly1305Key;

    static final int nonceSize = 12;

    @BeforeAll
    static void setUp() throws NoSuchAlgorithmException {
        chaCha20 = ChaCha20.create(ChaCha20.ChaCha20Setting.builder()
                .plain(str4096)
                .nonceSize(nonceSize)
                .encryptedOutput(chaCha20OutputEnc)
                .decryptedOutput(chaCha20OutputDec)
                .build());
        chaCha20Key = chaCha20.generateSecretKey();

        chaCha20Poly1305 = ChaCha20Poly1305.create(ChaCha20Poly1305.ChaCha20Poly1305Setting.builder()
                .plain(str4096)
                .nonceSize(nonceSize)
                .encryptedOutput(chaCha20Poly1305OutputEnc)
                .decryptedOutput(chaCha20Poly1305OutputDec)
                .build());
        chaCha20Poly1305Key = chaCha20Poly1305.generateSecretKey();
    }

    @Order(1)
    @DisplayName("ChaCha20 (스트리밍) 암호화 테스트")
    @Test
    void chaCha20Test() throws Exception {
        // 1. 일반 암호화/복호화 테스트
        byte[] plainBytes = chaCha20.getPlainBytes();
        byte[] ciphertext = chaCha20.encrypt(chaCha20Key, plainBytes, 100);
        log.info("ChaCha20 암호문: {}", Hex.toHexString(ciphertext));
        byte[] decryptedText = chaCha20.decrypt(chaCha20Key, ciphertext, 100);
        log.info("복호화: {}", new String(decryptedText));

        // 2. 스트리밍 암호화/복호화 테스트
        Path encryptedOutput = Objects.requireNonNull(chaCha20.getEncryptedOutput());
        Path decryptedOutput = Objects.requireNonNull(chaCha20.getDecryptedOutput());
        Files.writeString(decryptedOutput, "Is not real");

        log.info("스트리밍 암호화를 시작합니다...");
        int encResultSize = EntFile.byteBufferStreaming(commonInput, encryptedOutput, 4096, 4096 + 12, (inputBuffer, outputBuffer) -> {
            try {
                chaCha20.encryptStream(chaCha20Key, inputBuffer, outputBuffer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        log.info("스트리밍 암호화 완료. 쓰기 경로 및 사이즈: {}, {}", encryptedOutput, encResultSize);

        log.info("스트리밍 복호화를 시작합니다...");
        int decResultSize = EntFile.byteBufferStreaming(encryptedOutput, decryptedOutput, 4096, 4096 + 12, (inputBuffer, outputBuffer) -> {
            try {
                chaCha20.decryptStream(chaCha20Key, inputBuffer, outputBuffer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        log.info("스트리밍 암호화 완료. 쓰기 경로 및 사이즈: {}, {}", decryptedOutput, decResultSize);

        String originalContent = new String(Files.readAllBytes(commonInput));
        String decryptedContent = new String(Files.readAllBytes(decryptedOutput));
        assertEquals(originalContent, decryptedContent, "원본 내용과 복호화된 내용이 일치하는가?");
    }

    @Order(2)
    @DisplayName("ChaCha20-Poly1305 (스트리밍) 암호화 테스트")
    @Test
    void chaCha20_Poly1305Test() throws Exception {
        // 1. 일반 암호화/복호화 테스트
        byte[] plainBytes = chaCha20Poly1305.getPlainBytes();
        byte[] ciphertext = chaCha20Poly1305.encrypt(chaCha20Poly1305Key, plainBytes, 100);
        log.info("ChaCha20-Poly1305 암호문: {}", Hex.toHexString(ciphertext));
        byte[] decryptedText = chaCha20Poly1305.decrypt(chaCha20Poly1305Key, ciphertext, 100);
        log.info("복호화: {}", new String(decryptedText));

        // 2. 스트리밍 암호화/복호화 테스트
        Path encryptedOutput = Objects.requireNonNull(chaCha20Poly1305.getEncryptedOutput());
        Path decryptedOutput = Objects.requireNonNull(chaCha20Poly1305.getDecryptedOutput());
        Files.writeString(decryptedOutput, "Is not real");

        log.info("스트리밍 암호화를 시작합니다...");
        int encResultSize = EntFile.byteBufferStreaming(commonInput, encryptedOutput, 4096, 4096 + 12, (inputBuffer, outputBuffer) -> {
            try {
                chaCha20Poly1305.encryptStream(chaCha20Poly1305Key, inputBuffer, outputBuffer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        log.info("스트리밍 암호화 완료. 쓰기 경로 및 사이즈: {}, {}", encryptedOutput, encResultSize);

        log.info("스트리밍 복호화를 시작합니다...");
        int decResultSize = EntFile.byteBufferStreaming(encryptedOutput, decryptedOutput, 4096, 4096 + 12, (inputBuffer, outputBuffer) -> {
            try {
                chaCha20Poly1305.decryptStream(chaCha20Poly1305Key, inputBuffer, outputBuffer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        log.info("스트리밍 암호화 완료. 쓰기 경로 및 사이즈: {}, {}", decryptedOutput, decResultSize);

        String originalContent = new String(Files.readAllBytes(commonInput));
        String decryptedContent = new String(Files.readAllBytes(decryptedOutput));
        assertEquals(originalContent, decryptedContent, "원본 내용과 복호화된 내용이 일치하는가?");
    }

    @AfterAll
    static void tearDown() throws Exception {
//        log.info("20초 후 모든 작업 종료");
//        Thread.sleep(20000);

        chaCha20.close();
        chaCha20Poly1305.close();

        Files.delete(chaCha20OutputEnc);
        Files.delete(chaCha20OutputDec);
        Files.delete(chaCha20Poly1305OutputEnc);
        Files.delete(chaCha20Poly1305OutputDec);
        log.info("모든 작업 종료됨");
    }
}