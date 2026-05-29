/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.transport;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.iss.exception.IssException;
import space.qu4nt.entanglementlib.iss.exception.IssProtocolException;
import space.qu4nt.entanglementlib.iss.internal.SdcBytes;
import space.qu4nt.entanglementlib.iss.protocol.FrameHeader;
import space.qu4nt.entanglementlib.iss.protocol.Opcode;
import space.qu4nt.entanglementlib.iss.protocol.WireConstants;
import space.qu4nt.entanglementlib.security.crypto.ChaCha20;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/// 핸드셰이크가 끝난 소켓 위에서 ChaCha20-Poly1305 AEAD 레코드를 송수신하는 보안 채널입니다.
///
/// # Threading
/// 단일 연결 스레드 전용입니다(스레드 안전하지 않음). 서버는 연결별 가상 스레드에서, 클라이언트는
/// 호출 스레드에서 사용합니다.
///
/// # Scope Model
/// 연결 스코프는 방향별 대칭키를 보유하며 [#close()] 시 1회 소거됩니다. 레코드 처리에 쓰이는
/// nonce·AAD·평문·암호문 컨테이너는 레코드별 스코프에서 즉시 소거됩니다.
///
/// @author Q. T. Felix
public final class SecureChannel implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SecureChannel.class);

    private final Socket socket;
    private final ReadableByteChannel in;
    private final WritableByteChannel out;
    private final SDCScopeContext connScope;
    private final SessionKeys keys;

    private long seqTx = 0;
    private long seqRx = 0;
    private boolean closeSent = false;
    private boolean closeReceived = false;

    private SecureChannel(final Socket socket,
                          final ReadableByteChannel in,
                          final WritableByteChannel out,
                          final SDCScopeContext connScope,
                          final SessionKeys keys) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.connScope = connScope;
        this.keys = keys;
    }

    /// 소켓 위에서 PSK 상호 인증 핸드셰이크를 수행하고 보안 채널을 확립합니다.
    ///
    /// @param socket                연결된 소켓
    /// @param role                  참가자 역할
    /// @param psk                   사전 공유 키 (호출자 소유 컨테이너, 이 메소드가 소거하지 않음)
    /// @param handshakeTimeoutMillis 핸드셰이크 제한 시간
    /// @param idleTimeoutMillis     데이터 단계 유휴 읽기 제한 시간
    /// @throws IssException 핸드셰이크 실패 또는 IO 오류 시 (자원은 정리됨)
    public static @NotNull SecureChannel open(final @NotNull Socket socket,
                                              final @NotNull Role role,
                                              final @NotNull SensitiveDataContainer psk,
                                              final int handshakeTimeoutMillis,
                                              final int idleTimeoutMillis) throws IssException {
        SDCScopeContext connScope = null;
        try {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(handshakeTimeoutMillis);
            final ReadableByteChannel in = Channels.newChannel(socket.getInputStream());
            final WritableByteChannel out = Channels.newChannel(socket.getOutputStream());
            connScope = new SDCScopeContext();
            final SessionKeys keys = PskHandshake.perform(in, out, role, psk, connScope);
            socket.setSoTimeout(idleTimeoutMillis);
            return new SecureChannel(socket, in, out, connScope, keys);
        } catch (IOException e) {
            closeQuietly(connScope, socket);
            throw new IssProtocolException("핸드셰이크 IO 오류", e);
        } catch (IssException e) {
            closeQuietly(connScope, socket);
            throw e;
        } catch (RuntimeException e) {
            closeQuietly(connScope, socket);
            throw new IssException("핸드셰이크 중 예기치 못한 오류", e);
        }
    }

    /// 애플리케이션 페이로드를 AEAD 보호 레코드로 전송합니다.
    public void writeData(final byte @NotNull [] payload) throws IssException {
        writeRecord(Opcode.DATA, payload);
    }

    /// 다음 애플리케이션 레코드를 수신·복호화하여 평문을 반환합니다.
    ///
    /// @return 평문 페이로드. 상대가 인증된 [Opcode#CLOSE]를 보낸 경우 `null`
    public byte @Nullable [] readData() throws IssException {
        final Plain plain = readRecord();
        if (plain.opcode() == Opcode.CLOSE) {
            this.closeReceived = true;
            return null;
        }
        return plain.payload();
    }

    /// 인증된 종료 레코드를 전송합니다(트렁케이션 방어). 멱등합니다.
    public void sendClose() throws IssException {
        if (closeSent)
            return;
        writeRecord(Opcode.CLOSE, new byte[]{0});
        this.closeSent = true;
    }

    /// 상대로부터 인증된 종료 레코드를 수신했는지 여부입니다.
    public boolean isCloseReceived() {
        return closeReceived;
    }

    private void writeRecord(final Opcode opcode, final byte[] payload) throws IssException {
        if (seqTx == -1L)
            throw new IssProtocolException("시퀀스 한계 도달 (재연결 필요)");
        if (payload.length > WireConstants.MAX_FRAME - WireConstants.TAG_LEN)
            throw new IssProtocolException("페이로드가 최대 프레임 크기를 초과했습니다");

        final long seq = seqTx++;
        final int cipherLen = payload.length + WireConstants.TAG_LEN;
        final byte[] headerBytes = new FrameHeader(opcode, (byte) 0, seq, cipherLen).encode();

        try (SDCScopeContext rec = new SDCScopeContext()) {
            final SensitiveDataContainer nonce = rec.allocate(buildNonce(keys.ivTx, seq), true);
            final SensitiveDataContainer aad = rec.allocate(headerBytes.clone(), true);
            final SensitiveDataContainer plaintext = rec.allocate(payload.clone(), true);
            final SensitiveDataContainer ciphertext = ChaCha20.encrypt(rec, keys.keyTx, nonce, aad, plaintext);
            FrameHeader.writeFully(out, ByteBuffer.wrap(headerBytes));
            SensitiveDataContainer.transmitZeroCopy(ciphertext, out);
        } catch (ELIBSecurityProcessException e) {
            throw new IssException("레코드 암호화에 실패했습니다", e);
        }
    }

    private @NotNull Plain readRecord() throws IssException {
        final byte[] headerBytes = new byte[WireConstants.HEADER_LEN];
        FrameHeader.readFully(in, ByteBuffer.wrap(headerBytes));
        final FrameHeader header = FrameHeader.decode(headerBytes);

        if (header.seq() != seqRx)
            throw new IssProtocolException("시퀀스 번호가 일치하지 않습니다 (재전송/재정렬 거부)");

        final byte[] body = new byte[header.cipherLen()];
        FrameHeader.readFully(in, ByteBuffer.wrap(body));

        try (SDCScopeContext rec = new SDCScopeContext()) {
            final SensitiveDataContainer nonce = rec.allocate(buildNonce(keys.ivRx, header.seq()), true);
            final SensitiveDataContainer aad = rec.allocate(headerBytes.clone(), true);
            final SensitiveDataContainer ciphertext = rec.allocate(body, true);
            final SensitiveDataContainer plaintext = ChaCha20.decrypt(rec, keys.keyRx, nonce, aad, ciphertext);
            seqRx++;
            final byte[] result = SdcBytes.export(plaintext);
            return new Plain(header.opcode(), header.opcode() == Opcode.CLOSE ? new byte[0] : result);
        } catch (ELIBSecurityProcessException e) {
            throw new IssException("레코드 복호화에 실패했습니다 (인증 태그 불일치 또는 변조)", e);
        }
    }

    /// nonce = iv XOR (0x00000000 || seq_be64). seq를 IV 하위 8바이트에 우측 정렬로 XOR합니다.
    private static byte @NotNull [] buildNonce(final byte[] iv, final long seq) {
        final byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++)
            nonce[WireConstants.IV_LEN - 1 - i] ^= (byte) (seq >>> (8 * i));
        return nonce;
    }

    @Override
    public void close() {
        try {
            if (!closeSent && !closeReceived && socket.isConnected() && !socket.isClosed()) {
                try {
                    sendClose();
                } catch (Exception e) {
                    log.debug("종료 레코드 전송 실패(무시): {}", e.getMessage());
                }
            }
        } finally {
            keys.wipe();
            connScope.close();
            closeSocket(socket);
        }
    }

    private static void closeQuietly(final @Nullable SDCScopeContext scope, final @NotNull Socket socket) {
        if (scope != null)
            scope.close();
        closeSocket(socket);
    }

    private static void closeSocket(final Socket socket) {
        try {
            if (!socket.isClosed())
                socket.close();
        } catch (IOException ignored) {
            // 소켓 종료 실패는 소거 결과에 영향을 주지 않음
        }
    }

    private record Plain(Opcode opcode, byte[] payload) {
    }
}
