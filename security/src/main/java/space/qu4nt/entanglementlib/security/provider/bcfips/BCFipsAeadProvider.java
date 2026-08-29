package space.qu4nt.entanglementlib.security.provider.bcfips;

import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InputAEADDecryptor;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputAEADEncryptor;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.general.ChaCha20;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.AeadProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/// BouncyCastle FIPS 경량 API를 사용하는 ChaCha20-Poly1305 [AeadProvider] 구현입니다.
///
/// RFC 8439 AEAD 구조(암호문 뒤에 16바이트 태그 부착)를 따르며, JCA `Provider` 전역 등록 없이
/// [ChaCha20.AEADOperatorFactory]를 직접 호출합니다.
///
/// # Limitation
/// `ChaCha20-Poly1305`는 FIPS 승인 알고리즘이 아니라 `bc-fips`의 `general` 계열에 속합니다. 따라서
/// `approved-only` 모드([CryptoServicesRegistrar#setApprovedOnlyMode])가 켜진 스레드에서는 이 공급자의
/// 연산이 거부되며, 라이브러리는 이를 감지해 [ELIBSecurityProcessException]으로 변환합니다.
/// FIPS 승인 AEAD가 필요하면 AES-GCM 기반 사용자 정의 공급자를 주입하세요.
@ApiStatus.Internal
public final class BCFipsAeadProvider implements AeadProvider {

    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int MAC_SIZE_BITS = TAG_BYTES * 8;

    private final ChaCha20.AEADOperatorFactory factory = new ChaCha20.AEADOperatorFactory();

    @Override
    public SensitiveDataContainer encrypt(final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer key,
                                          final @NotNull SensitiveDataContainer nonce,
                                          final @Nullable SensitiveDataContainer aad,
                                          final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {
        ensureApprovedOnlyModeOff();

        byte[] keyBytes = null;
        byte[] nonceBytes = null;
        byte[] aadBytes = null;
        byte[] inBytes = null;
        byte[] outBytes = null;
        SymmetricSecretKey secretKey = null;
        WipeableSink sink = null;
        try {
            keyBytes = SDCCodec.read(key);
            nonceBytes = SDCCodec.read(nonce);
            validateKeyAndNonce(keyBytes, nonceBytes);
            inBytes = SDCCodec.read(plaintext);

            secretKey = new SymmetricSecretKey(ChaCha20.ALGORITHM, keyBytes);
            final OutputAEADEncryptor<ChaCha20.AuthParameters> encryptor =
                    factory.createOutputAEADEncryptor(secretKey, authParameters(nonceBytes));

            if (aad != null) {
                aadBytes = SDCCodec.read(aad);
                if (aadBytes.length > 0)
                    encryptor.getAADStream().update(aadBytes);
            }

            sink = new WipeableSink(inBytes.length + TAG_BYTES);
            try (CipherOutputStream cipherOut = encryptor.getEncryptingStream(sink)) {
                cipherOut.write(inBytes);
            }

            outBytes = sink.snapshot();
            return SDCCodec.write(scope, outBytes);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("BouncyCastle FIPS AEAD 암호화 중 치명적 예외가 발생했습니다!", t);
        } finally {
            destroyQuietly(secretKey);
            if (sink != null) sink.wipe();
            SDCCodec.wipe(keyBytes, nonceBytes, aadBytes, inBytes, outBytes);
        }
    }

    @Override
    public SensitiveDataContainer decrypt(final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer key,
                                          final @NotNull SensitiveDataContainer nonce,
                                          final @Nullable SensitiveDataContainer aad,
                                          final @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException {
        ensureApprovedOnlyModeOff();

        byte[] keyBytes = null;
        byte[] nonceBytes = null;
        byte[] aadBytes = null;
        byte[] inBytes = null;
        byte[] outBytes = null;
        byte[] chunk = null;
        SymmetricSecretKey secretKey = null;
        WipeableSink sink = null;
        try {
            keyBytes = SDCCodec.read(key);
            nonceBytes = SDCCodec.read(nonce);
            validateKeyAndNonce(keyBytes, nonceBytes);
            inBytes = SDCCodec.read(ciphertext);
            if (inBytes.length < TAG_BYTES)
                throw new ELIBSecurityIllegalArgumentException(
                        "ChaCha20-Poly1305 암호문은 최소 " + TAG_BYTES + "바이트 태그를 포함해야 합니다 (실제: " + inBytes.length + ")");

            secretKey = new SymmetricSecretKey(ChaCha20.ALGORITHM, keyBytes);
            final InputAEADDecryptor<ChaCha20.AuthParameters> decryptor =
                    factory.createInputAEADDecryptor(secretKey, authParameters(nonceBytes));

            if (aad != null) {
                aadBytes = SDCCodec.read(aad);
                if (aadBytes.length > 0)
                    decryptor.getAADStream().update(aadBytes);
            }

            sink = new WipeableSink(inBytes.length - TAG_BYTES);
            chunk = new byte[4096];
            try (InputStream plainIn = decryptor.getDecryptingStream(new ByteArrayInputStream(inBytes))) {
                int read;
                while ((read = plainIn.read(chunk)) >= 0)
                    sink.write(chunk, 0, read);
            }

            outBytes = sink.snapshot();
            return SDCCodec.write(scope, outBytes);
        } catch (InvalidCipherTextException e) {
            throw new ELIBSecurityProcessException("ChaCha20-Poly1305 인증 태그 검증에 실패했습니다 (무결성 위반 또는 잘못된 키/Nonce/AAD)!", e);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("BouncyCastle FIPS AEAD 복호화 중 치명적 예외가 발생했습니다!", t);
        } finally {
            destroyQuietly(secretKey);
            if (sink != null) sink.wipe();
            SDCCodec.wipe(keyBytes, nonceBytes, aadBytes, inBytes, outBytes, chunk);
        }
    }

    @Override
    public @NotNull String backendName() {
        return "BouncyCastle FIPS ChaCha20-Poly1305 (FIPS 미승인 알고리즘)";
    }

    private static ChaCha20.AuthParameters authParameters(final byte @NotNull [] nonceBytes) {
        return ChaCha20.WithPoly1305.withIV(nonceBytes).withMACSize(MAC_SIZE_BITS);
    }

    private static void validateKeyAndNonce(final byte @NotNull [] keyBytes, final byte @NotNull [] nonceBytes) {
        if (keyBytes.length != KEY_BYTES)
            throw new ELIBSecurityIllegalArgumentException("ChaCha20-Poly1305 키는 32바이트여야 합니다 (실제: " + keyBytes.length + ")");
        if (nonceBytes.length != NONCE_BYTES)
            throw new ELIBSecurityIllegalArgumentException("ChaCha20-Poly1305 Nonce는 12바이트여야 합니다 (실제: " + nonceBytes.length + ")");
    }

    /// `approved-only` 모드에서는 미승인 알고리즘 팩토리 생성이 [Error]로 거부되므로 사전에 차단한다
    private static void ensureApprovedOnlyModeOff() throws ELIBSecurityProcessException {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            throw new ELIBSecurityProcessException(
                    "ChaCha20-Poly1305은 FIPS 승인 알고리즘이 아니므로 approved-only 모드에서 사용할 수 없습니다. "
                            + "approved-only 모드를 해제하거나 FIPS 승인 AEAD 사용자 정의 공급자를 주입하세요.");
    }

    private static void destroyQuietly(final @Nullable SymmetricSecretKey secretKey) {
        if (secretKey == null || secretKey.isDestroyed()) return;
        try {
            secretKey.destroy();
        } catch (Throwable ignored) {
            // 연산은 이미 종료되었으므로 소거 실패를 전파하지 않는다
        }
    }

    /// 내부 버퍼를 직접 0으로 소거할 수 있는 출력 싱크입니다.
    ///
    /// [java.io.ByteArrayOutputStream]은 내부 버퍼를 노출하지 않아 `heap` 잔류 데이터를 소거할 수
    /// 없으므로 대신 사용합니다. 버퍼가 확장될 때 이전 버퍼도 즉시 소거합니다.
    private static final class WipeableSink extends OutputStream {

        private byte[] buffer;
        private int position;

        private WipeableSink(final int expectedSize) {
            this.buffer = new byte[Math.max(expectedSize, 32)];
        }

        @Override
        public void write(final int b) {
            ensureCapacity(1);
            buffer[position++] = (byte) b;
        }

        @Override
        public void write(final byte @NotNull [] source, final int offset, final int length) {
            ensureCapacity(length);
            System.arraycopy(source, offset, buffer, position, length);
            position += length;
        }

        private void ensureCapacity(final int extra) {
            if (position + extra <= buffer.length) return;
            final byte[] grown = new byte[Math.max(buffer.length * 2, position + extra)];
            System.arraycopy(buffer, 0, grown, 0, position);
            Arrays.fill(buffer, (byte) 0);
            buffer = grown;
        }

        private byte[] snapshot() {
            return Arrays.copyOf(buffer, position);
        }

        private void wipe() {
            Arrays.fill(buffer, (byte) 0);
            position = 0;
        }
    }
}
