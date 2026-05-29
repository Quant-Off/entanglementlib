/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.iss.exception.ISSException;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;
import space.qu4nt.entanglementlib.iss.handler.ISSRequest;
import space.qu4nt.entanglementlib.iss.handler.ISSResponse;
import space.qu4nt.entanglementlib.iss.handler.ISSStatus;
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
public final class ISSClient implements AutoCloseable {

    private final SecureChannel channel;

    private ISSClient(final SecureChannel channel) {
        this.channel = channel;
    }

    /// 서버에 접속하고 PSK 상호 인증 핸드셰이크를 수행합니다.
    public static @NotNull ISSClient connect(final @NotNull ISSClientConfig config) throws ISSException {
        final Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(config.host(), config.port()), config.connectTimeoutMillis());
        } catch (IOException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // 무시
            }
            throw new ISSException("서버 접속에 실패했습니다: " + config.host() + ":" + config.port(), e);
        }
        final SecureChannel channel = SecureChannel.open(
                socket, Role.CLIENT, config.psk(),
                config.handshakeTimeoutMillis(), config.idleTimeoutMillis());
        return new ISSClient(channel);
    }

    /// 일반 요청을 전송하고 응답을 수신합니다(커스텀 명령 포함).
    public @NotNull ISSResponse request(final @NotNull String command, final byte @NotNull [] body) throws ISSException {
        channel.writeData(new ISSRequest(command, body).encode());
        final byte[] responseBytes = channel.readData();
        if (responseBytes == null)
            throw new ISSProtocolException("서버가 응답 없이 세션을 종료했습니다");
        return ISSResponse.decode(responseBytes);
    }

    public void ping() throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.PING, new byte[0]);
        if (!response.status().isOk())
            throw new ISSException("PING 실패: " + response.status());
    }

    public void put(final @NotNull String key, final byte @NotNull [] value) throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.PUT, KvCodec.encodeKeyValue(key, value));
        if (!response.status().isOk())
            throw new ISSException("PUT 실패: " + response.status());
    }

    /// 키의 값을 반환합니다. 없으면 `null`.
    public byte @Nullable [] get(final @NotNull String key) throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.GET, KvCodec.encodeKey(key));
        if (response.status() == ISSStatus.NOT_FOUND)
            return null;
        if (!response.status().isOk())
            throw new ISSException("GET 실패: " + response.status());
        return response.body();
    }

    /// 키를 삭제합니다. 존재했으면 true.
    public boolean delete(final @NotNull String key) throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.DEL, KvCodec.encodeKey(key));
        if (response.status() == ISSStatus.NOT_FOUND)
            return false;
        if (!response.status().isOk())
            throw new ISSException("DEL 실패: " + response.status());
        return true;
    }

    public boolean exists(final @NotNull String key) throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.EXISTS, KvCodec.encodeKey(key));
        if (!response.status().isOk())
            throw new ISSException("EXISTS 실패: " + response.status());
        final byte[] body = response.body();
        return body.length > 0 && body[0] != 0;
    }

    public @NotNull List<String> list() throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.LIST, new byte[0]);
        if (!response.status().isOk())
            throw new ISSException("LIST 실패: " + response.status());
        final String text = response.bodyAsText();
        if (text.isEmpty())
            return List.of();
        return List.of(text.split("\n"));
    }

    public @NotNull String status() throws ISSException {
        final ISSResponse response = request(BuiltinHandlers.STATUS, new byte[0]);
        if (!response.status().isOk())
            throw new ISSException("STATUS 실패: " + response.status());
        return response.bodyAsText();
    }

    @Override
    public void close() {
        channel.close();
    }
}
