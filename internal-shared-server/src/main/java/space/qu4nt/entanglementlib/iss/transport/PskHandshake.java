/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.transport;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.iss.exception.ISSAuthException;
import space.qu4nt.entanglementlib.iss.exception.ISSException;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;
import space.qu4nt.entanglementlib.iss.internal.SDCBytes;
import space.qu4nt.entanglementlib.iss.protocol.FrameHeader;
import space.qu4nt.entanglementlib.iss.protocol.WireConstants;
import space.qu4nt.entanglementlib.security.crypto.rng.RNG;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.MessageDigest;
import java.util.Arrays;

/// 폐쇄망 PSK 상호 인증 핸드셰이크입니다.
///
/// 공개 인터넷 CA 신뢰 체인을 배제하고, 사전 공유 키(PSK)에서 유도한 키 확인(Finished) 값으로
/// 양측을 상호 인증합니다. PSK를 보유하지 않은 중간자는 어느 쪽 Finished도 위조할 수 없으므로
/// MITM이 차단되며, 트랜스크립트를 바인딩하여 난수/스위트 다운그레이드를 탐지합니다.
///
/// # Limitation
/// 순방향 비밀성(PFS)을 제공하지 않습니다. DH/KEM 원시연산이 검증 백엔드에 노출되지 않으므로
/// 해시·대칭암호만으로는 불가능합니다. PSK가 노출되면 과거·미래 트래픽이 복호화될 수 있으며,
/// 에어갭·강한 PSK·주기적 PSK 교체로 완화합니다.
///
/// @author Q. T. Felix
final class PskHandshake {

    private PskHandshake() {
        throw new AssertionError("cannot access");
    }

    /// 핸드셰이크를 수행하고 확립된 세션 키를 반환합니다. 대칭키는 `connScope`에 귀속됩니다.
    ///
    /// @throws ISSAuthException     Finished 불일치(PSK 불일치 또는 변조) 시
    /// @throws ISSProtocolException 와이어 포맷 위반 또는 다운그레이드 시도 시
    static @NotNull SessionKeys perform(final @NotNull ReadableByteChannel in,
                                        final @NotNull WritableByteChannel out,
                                        final @NotNull Role role,
                                        final @NotNull SensitiveDataContainer psk,
                                        final @NotNull SDCScopeContext connScope)
            throws ISSException {
        try (SDCScopeContext hs = new SDCScopeContext()) {
            final byte[] clientRandom;
            final byte[] serverRandom;
            final byte suite = WireConstants.SUITE_CHACHA20POLY1305_SHA3_256;

            if (role == Role.CLIENT) {
                clientRandom = randomBytes(hs, WireConstants.RANDOM_LEN);
                writeClientHello(out, suite, clientRandom);
                final byte[] serverHello = readExactly(in, WireConstants.RANDOM_LEN + 1);
                if (serverHello[WireConstants.RANDOM_LEN] != suite)
                    throw new ISSProtocolException("서버가 스위트를 다운그레이드했습니다");
                serverRandom = Arrays.copyOf(serverHello, WireConstants.RANDOM_LEN);
            } else {
                final byte[] clientHello = readExactly(in, 4 + 1 + 1 + WireConstants.RANDOM_LEN);
                final ByteBuffer hb = ByteBuffer.wrap(clientHello);
                if (hb.getInt() != WireConstants.MAGIC)
                    throw new ISSProtocolException("프로토콜 식별자가 일치하지 않습니다");
                if (hb.get() != WireConstants.VERSION)
                    throw new ISSProtocolException("지원하지 않는 프로토콜 버전입니다");
                if (hb.get() != suite)
                    throw new ISSProtocolException("지원하지 않는 암호 스위트입니다");
                clientRandom = new byte[WireConstants.RANDOM_LEN];
                hb.get(clientRandom);
                serverRandom = randomBytes(hs, WireConstants.RANDOM_LEN);
                writeServerHello(out, suite, serverRandom);
            }

            // 키 유도 자료
            final byte[] psk32 = derivePsk32(hs, psk);
            final byte[] master = Kdf.sha3_256(hs, psk32,
                    new byte[]{WireConstants.VERSION}, new byte[]{suite}, clientRandom, serverRandom);
            Arrays.fill(psk32, (byte) 0);

            final byte[] kC2s = Kdf.sha3_256(hs, master, Kdf.label(WireConstants.LABEL_K_C2S));
            final byte[] kS2c = Kdf.sha3_256(hs, master, Kdf.label(WireConstants.LABEL_K_S2C));
            final byte[] ivC2s = first(Kdf.sha3_256(hs, master, Kdf.label(WireConstants.LABEL_IV_C2S)), WireConstants.IV_LEN);
            final byte[] ivS2c = first(Kdf.sha3_256(hs, master, Kdf.label(WireConstants.LABEL_IV_S2C)), WireConstants.IV_LEN);
            final byte[] kFinished = Kdf.sha3_256(hs, master, Kdf.label(WireConstants.LABEL_FINISHED));
            Arrays.fill(master, (byte) 0);

            // 트랜스크립트 바인딩 (모든 협상 필드 포함)
            final byte[] transcript = transcript(suite, clientRandom, serverRandom);
            final byte[] clientFinished = Kdf.sha3_256(hs, kFinished, new byte[]{WireConstants.FINISHED_CLIENT}, transcript);
            final byte[] serverFinished = Kdf.sha3_256(hs, kFinished, new byte[]{WireConstants.FINISHED_SERVER}, transcript);
            Arrays.fill(kFinished, (byte) 0);

            // 키 확인 교환 (검증 전 어떤 레코드도 수용/송신 금지)
            if (role == Role.CLIENT) {
                writeExactly(out, clientFinished);
                final byte[] peer = readExactly(in, 32);
                if (!MessageDigest.isEqual(peer, serverFinished))
                    throw new ISSAuthException("서버 키 확인에 실패했습니다 (PSK 불일치 또는 변조)");
            } else {
                final byte[] peer = readExactly(in, 32);
                if (!MessageDigest.isEqual(peer, clientFinished))
                    throw new ISSAuthException("클라이언트 키 확인에 실패했습니다 (PSK 불일치 또는 변조)");
                writeExactly(out, serverFinished);
            }
            Arrays.fill(clientFinished, (byte) 0);
            Arrays.fill(serverFinished, (byte) 0);

            // 장수 키를 연결 스코프로 이전 (heap 키 자료는 바인딩 시 소거)
            final SensitiveDataContainer kc2sSdc = connScope.allocate(kC2s, true);
            final SensitiveDataContainer ks2cSdc = connScope.allocate(kS2c, true);

            return (role == Role.CLIENT)
                    ? new SessionKeys(kc2sSdc, ks2cSdc, ivC2s, ivS2c)
                    : new SessionKeys(ks2cSdc, kc2sSdc, ivS2c, ivC2s);
        } catch (ELIBSecurityProcessException e) {
            throw new ISSException("핸드셰이크 암호 연산에 실패했습니다", e);
        }
    }

    private static byte @NotNull [] derivePsk32(final SDCScopeContext hs, final SensitiveDataContainer psk)
            throws ELIBSecurityProcessException {
        final byte[] raw = SDCBytes.export(psk);
        try {
            return Kdf.sha3_256(hs, new byte[]{WireConstants.PSK_CANON_DOMAIN}, raw);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static byte @NotNull [] transcript(final byte suite, final byte[] clientRandom, final byte[] serverRandom) {
        final ByteBuffer buf = ByteBuffer.allocate(4 + 1 + 1 + clientRandom.length + serverRandom.length);
        buf.putInt(WireConstants.MAGIC);
        buf.put(WireConstants.VERSION);
        buf.put(suite);
        buf.put(clientRandom);
        buf.put(serverRandom);
        return buf.array();
    }

    private static byte @NotNull [] randomBytes(final SDCScopeContext scope, final int len)
            throws ELIBSecurityProcessException {
        final SensitiveDataContainer r = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, len);
        return SDCBytes.export(r);
    }

    private static byte @NotNull [] first(final byte[] source, final int len) {
        final byte[] out = Arrays.copyOf(source, len);
        Arrays.fill(source, (byte) 0);
        return out;
    }

    private static void writeClientHello(final WritableByteChannel out, final byte suite, final byte[] clientRandom)
            throws ISSProtocolException {
        final ByteBuffer buf = ByteBuffer.allocate(4 + 1 + 1 + clientRandom.length);
        buf.putInt(WireConstants.MAGIC);
        buf.put(WireConstants.VERSION);
        buf.put(suite);
        buf.put(clientRandom);
        buf.flip();
        FrameHeader.writeFully(out, buf);
    }

    private static void writeServerHello(final WritableByteChannel out, final byte suite, final byte[] serverRandom)
            throws ISSProtocolException {
        final ByteBuffer buf = ByteBuffer.allocate(serverRandom.length + 1);
        buf.put(serverRandom);
        buf.put(suite);
        buf.flip();
        FrameHeader.writeFully(out, buf);
    }

    private static byte @NotNull [] readExactly(final ReadableByteChannel in, final int len)
            throws ISSProtocolException {
        final ByteBuffer buf = ByteBuffer.allocate(len);
        FrameHeader.readFully(in, buf);
        return buf.array();
    }

    private static void writeExactly(final WritableByteChannel out, final byte[] data)
            throws ISSProtocolException {
        FrameHeader.writeFully(out, ByteBuffer.wrap(data));
    }
}
