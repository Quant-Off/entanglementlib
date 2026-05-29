/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.iss.exception.IssException;
import space.qu4nt.entanglementlib.iss.handler.HandlerRegistry;
import space.qu4nt.entanglementlib.iss.handler.IssRequest;
import space.qu4nt.entanglementlib.iss.handler.IssRequestContext;
import space.qu4nt.entanglementlib.iss.handler.IssRequestHandler;
import space.qu4nt.entanglementlib.iss.handler.IssResponse;
import space.qu4nt.entanglementlib.iss.protocol.WireConstants;
import space.qu4nt.entanglementlib.iss.security.BindPolicy;
import space.qu4nt.entanglementlib.iss.service.BuiltinHandlers;
import space.qu4nt.entanglementlib.iss.service.SharedStore;
import space.qu4nt.entanglementlib.iss.transport.Role;
import space.qu4nt.entanglementlib.iss.transport.SecureChannel;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/// 폐쇄망 내부 공유 서버입니다.
///
/// 기본 127.0.0.1에 바인드하여 연결마다 PSK 상호 인증을 수행하고, 인증된 세션 위에서 명령을
/// 디스패치합니다. 연결 처리는 연결별 가상 스레드에서 수행됩니다. 내장 공유 저장소(PUT/GET/DEL/
/// LIST/EXISTS) 및 PING/STATUS 핸들러가 자동 등록되며, [#register]로 커스텀 명령을 추가할 수
/// 있습니다.
///
/// # Arena Mode
/// 공유 저장소 값과 PSK 컨테이너가 연결 스레드 간에 공유되므로, 보안 모듈을 `SHARED` arena 모드로
/// 초기화해야 합니다. 그렇지 않으면 교차 스레드 접근 시 오류가 발생합니다.
///
/// @author Q. T. Felix
public final class IssServer implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(IssServer.class);

    private final IssServerConfig config;
    private final HandlerRegistry registry = new HandlerRegistry();
    private final SharedStore store = new SharedStore();
    private final Semaphore connectionLimit;
    private final ExecutorService connectionExecutor =
            Executors.newVirtualThreadPerTaskExecutor();

    private volatile boolean running = false;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private int boundPort = -1;

    private IssServer(final IssServerConfig config) {
        this.config = config;
        this.connectionLimit = new Semaphore(config.maxConnections());
        BuiltinHandlers.registerAll(registry, store, this::statusText);
    }

    public static @NotNull Builder builder() {
        return new Builder();
    }

    /// 커스텀 명령 핸들러를 등록합니다(시작 전·후 모두 가능).
    public void register(final @NotNull String command, final @NotNull IssRequestHandler handler) {
        registry.register(command, handler);
    }

    /// 내장 공유 저장소에 직접 접근합니다(코드레벨 사전 적재 등).
    public @NotNull SharedStore store() {
        return store;
    }

    /// 실제 바인드된 포트입니다. [#start()] 이후에만 유효합니다.
    public int port() {
        return boundPort;
    }

    /// 서버를 바인드하고 수용 루프를 시작합니다. 비차단입니다.
    public synchronized void start() throws IssException {
        if (running)
            throw new IssException("서버가 이미 실행 중입니다");

        final InetAddress address = BindPolicy.resolve(config.bindHost());
        BindPolicy.validateBind(address, config.allowNonLoopback());

        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(address, config.port()), 16);
            boundPort = serverSocket.getLocalPort();
        } catch (IOException e) {
            throw new IssException("서버 바인드에 실패했습니다", e);
        }

        running = true;
        acceptThread = new Thread(this::acceptLoop, "iss-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        log.info("ISS 서버 시작: {}:{} (최대 연결 {})", address.getHostAddress(), boundPort, config.maxConnections());
    }

    private void acceptLoop() {
        while (running) {
            final Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running)
                    log.debug("수용 루프 종료: {}", e.toString());
                break;
            }
            if (!connectionLimit.tryAcquire()) {
                log.warn("최대 동시 연결 수 초과로 연결을 거부합니다");
                closeSocket(socket);
                continue;
            }
            connectionExecutor.submit(() -> handleConnection(socket));
        }
    }

    private void handleConnection(final Socket socket) {
        final InetAddress peer = socket.getInetAddress();
        try {
            if (!BindPolicy.isPeerAllowed(peer, config.peerAllowlist())) {
                log.warn("허용목록에 없는 피어를 거부합니다: {}", peer);
                closeSocket(socket);
                return;
            }
            try (SecureChannel channel = SecureChannel.open(
                    socket, Role.SERVER, config.psk(),
                    config.handshakeTimeoutMillis(), config.idleTimeoutMillis())) {
                serve(channel, peer);
            }
        } catch (Exception e) {
            // fail-closed: 상세는 로컬 로깅으로만
            log.debug("연결 처리 실패(fail-closed): {}", e.toString());
            closeSocket(socket);
        } finally {
            connectionLimit.release();
        }
    }

    private void serve(final SecureChannel channel, final InetAddress peer) throws IssException {
        while (running) {
            final byte[] requestBytes = channel.readData();
            if (requestBytes == null)
                break; // 인증된 종료 수신

            IssResponse response;
            try {
                final IssRequest request = IssRequest.decode(requestBytes);
                final IssRequestHandler handler = registry.resolve(request.command());
                if (handler == null) {
                    response = IssResponse.unknownCommand(request.command());
                } else {
                    response = handler.handle(new IssRequestContext(request.command(), request.body(), peer));
                }
            } catch (Exception e) {
                log.debug("요청 처리 오류(fail-closed): {}", e.toString());
                response = IssResponse.error("요청 처리에 실패했습니다");
            }
            channel.writeData(response.encode());
        }
    }

    private String statusText() {
        final int active = config.maxConnections() - connectionLimit.availablePermits();
        return "ISS SERVER\n"
                + "bind=" + config.bindHost() + "\n"
                + "port=" + boundPort + "\n"
                + "connections=" + active + "/" + config.maxConnections() + "\n"
                + "store_keys=" + store.size();
    }

    /// 서버를 정지하고 공유 저장소를 소거합니다. PSK 컨테이너는 호출자 소유이므로 닫지 않습니다.
    @Override
    public synchronized void close() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed())
                serverSocket.close();
        } catch (IOException ignored) {
            // 무시
        }
        connectionExecutor.shutdownNow();
        try {
            connectionExecutor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        store.close();
        log.info("ISS 서버 종료");
    }

    private static void closeSocket(final Socket socket) {
        try {
            if (!socket.isClosed())
                socket.close();
        } catch (IOException ignored) {
            // 무시
        }
    }

    /// [IssServer] 빌더입니다.
    public static final class Builder {

        private String bindHost = "127.0.0.1";
        private int port = -1;
        private SensitiveDataContainer psk;
        private int maxConnections = WireConstants.DEFAULT_MAX_CONNECTIONS;
        private int handshakeTimeoutMillis = WireConstants.HANDSHAKE_TIMEOUT_MILLIS;
        private int idleTimeoutMillis = WireConstants.IDLE_READ_TIMEOUT_MILLIS;
        private boolean allowNonLoopback = false;
        private final List<InetAddress> peerAllowlist = new ArrayList<>();

        private Builder() {
        }

        public @NotNull Builder bindHost(final @NotNull String host) {
            this.bindHost = Objects.requireNonNull(host, "host");
            return this;
        }

        public @NotNull Builder port(final int port) {
            this.port = port;
            return this;
        }

        public @NotNull Builder psk(final @NotNull SensitiveDataContainer psk) {
            this.psk = psk;
            return this;
        }

        public @NotNull Builder maxConnections(final int max) {
            this.maxConnections = max;
            return this;
        }

        public @NotNull Builder handshakeTimeoutMillis(final int millis) {
            this.handshakeTimeoutMillis = millis;
            return this;
        }

        public @NotNull Builder idleTimeoutMillis(final int millis) {
            this.idleTimeoutMillis = millis;
            return this;
        }

        public @NotNull Builder allowNonLoopback(final boolean allow) {
            this.allowNonLoopback = allow;
            return this;
        }

        public @NotNull Builder allowPeer(final @NotNull InetAddress peer) {
            this.peerAllowlist.add(Objects.requireNonNull(peer, "peer"));
            return this;
        }

        public @NotNull IssServer build() {
            Objects.requireNonNull(psk, "psk");
            if (port < 0 || port > 65535)
                throw new IllegalArgumentException("포트가 유효하지 않습니다: " + port);
            if (maxConnections < 1)
                throw new IllegalArgumentException("최대 연결 수는 1 이상이어야 합니다");
            return new IssServer(new IssServerConfig(
                    bindHost, port, psk, maxConnections,
                    handshakeTimeoutMillis, idleTimeoutMillis, allowNonLoopback,
                    List.copyOf(peerAllowlist)));
        }
    }
}
