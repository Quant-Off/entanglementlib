/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.iss.exception.IssException;
import space.qu4nt.entanglementlib.iss.exception.IssProtocolException;
import space.qu4nt.entanglementlib.iss.handler.IssRequest;
import space.qu4nt.entanglementlib.iss.handler.IssResponse;
import space.qu4nt.entanglementlib.iss.handler.IssStatus;
import space.qu4nt.entanglementlib.iss.handler.KvCodec;
import space.qu4nt.entanglementlib.iss.service.BuiltinHandlers;
import space.qu4nt.entanglementlib.iss.transport.Role;
import space.qu4nt.entanglementlib.iss.transport.SecureChannel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;

/// 폐쇄망 내부 공유 서버에 접속하는 클라이언트입니다.
///
/// # Threading
/// 단일 스레드 전용입니다. 요청과 응답은 순차적으로 짝지어집니다.
///
/// @author Q. T. Felix
public final class IssClient implements AutoCloseable {

    private final SecureChannel channel;

    private IssClient(final SecureChannel channel) {
        this.channel = channel;
    }

    /// 서버에 접속하고 PSK 상호 인증 핸드셰이크를 수행합니다.
    public static @NotNull IssClient connect(final @NotNull IssClientConfig config) throws IssException {
        final Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(config.host(), config.port()), config.connectTimeoutMillis());
        } catch (IOException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // 무시
            }
            throw new IssException("서버 접속에 실패했습니다: " + config.host() + ":" + config.port(), e);
        }
        final SecureChannel channel = SecureChannel.open(
                socket, Role.CLIENT, config.psk(),
                config.handshakeTimeoutMillis(), config.idleTimeoutMillis());
        return new IssClient(channel);
    }

    /// 일반 요청을 전송하고 응답을 수신합니다(커스텀 명령 포함).
    public @NotNull IssResponse request(final @NotNull String command, final byte @NotNull [] body) throws IssException {
        channel.writeData(new IssRequest(command, body).encode());
        final byte[] responseBytes = channel.readData();
        if (responseBytes == null)
            throw new IssProtocolException("서버가 응답 없이 세션을 종료했습니다");
        return IssResponse.decode(responseBytes);
    }

    public void ping() throws IssException {
        final IssResponse response = request(BuiltinHandlers.PING, new byte[0]);
        if (!response.status().isOk())
            throw new IssException("PING 실패: " + response.status());
    }

    public void put(final @NotNull String key, final byte @NotNull [] value) throws IssException {
        final IssResponse response = request(BuiltinHandlers.PUT, KvCodec.encodeKeyValue(key, value));
        if (!response.status().isOk())
            throw new IssException("PUT 실패: " + response.status());
    }

    /// 키의 값을 반환합니다. 없으면 `null`.
    public byte @Nullable [] get(final @NotNull String key) throws IssException {
        final IssResponse response = request(BuiltinHandlers.GET, KvCodec.encodeKey(key));
        if (response.status() == IssStatus.NOT_FOUND)
            return null;
        if (!response.status().isOk())
            throw new IssException("GET 실패: " + response.status());
        return response.body();
    }

    /// 키를 삭제합니다. 존재했으면 true.
    public boolean delete(final @NotNull String key) throws IssException {
        final IssResponse response = request(BuiltinHandlers.DEL, KvCodec.encodeKey(key));
        if (response.status() == IssStatus.NOT_FOUND)
            return false;
        if (!response.status().isOk())
            throw new IssException("DEL 실패: " + response.status());
        return true;
    }

    public boolean exists(final @NotNull String key) throws IssException {
        final IssResponse response = request(BuiltinHandlers.EXISTS, KvCodec.encodeKey(key));
        if (!response.status().isOk())
            throw new IssException("EXISTS 실패: " + response.status());
        final byte[] body = response.body();
        return body.length > 0 && body[0] != 0;
    }

    public @NotNull List<String> list() throws IssException {
        final IssResponse response = request(BuiltinHandlers.LIST, new byte[0]);
        if (!response.status().isOk())
            throw new IssException("LIST 실패: " + response.status());
        final String text = response.bodyAsText();
        if (text.isEmpty())
            return List.of();
        return List.of(text.split("\n"));
    }

    public @NotNull String status() throws IssException {
        final IssResponse response = request(BuiltinHandlers.STATUS, new byte[0]);
        if (!response.status().isOk())
            throw new IssException("STATUS 실패: " + response.status());
        return response.bodyAsText();
    }

    @Override
    public void close() {
        channel.close();
    }
}
