/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.tls;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.exception.server.EntLibServerIllegalStateException;
import space.qu4nt.entanglementlib.exception.server.EntLibServerSecurityWarningException;
import space.qu4nt.entanglementlib.exception.session.EntLibSessionException;
import space.qu4nt.entanglementlib.security.communication.session.*;
import space.qu4nt.entanglementlib.security.crypto.*;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.NativeEntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.MLKEMKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.X25519KeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.X25519MLKEM768KeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.BlockCipherStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.CipherStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeECDHStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeKEMStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/// PQC를 지원하는 TLS 서버 구현체입니다.
///
/// 이 서버는 NIO(Non-blocking I/O)를 사용하여 다수의 클라이언트 연결을
/// 효율적으로 처리합니다. ML-KEM, X25519 등의 키 캡슐화 메커니즘을 통해
/// 양자 내성 보안 통신을 제공합니다.
///
/// ## 주요 기능
/// - NIO 기반 비동기 네트워크 처리
/// - 세션 기반 연결 관리
/// - 양자-내성 키 교환 (ML-KEM-512/768/1024)
/// - 하이브리드 모드 (X25519 + ML-KEM)
/// - 자동 핸드셰이크 타임아웃 처리
///
/// ## 사용 예시
/// ```java
/// ServerConfig config = ServerConfig.builder()
///     .port(8443)
///     .sessionConfig(SessionConfig.highSecurity())
///     .build();
///
/// Server server = new Server(config);
/// server.start();
/// ```
///
/// @author Q. T. Felix
/// @see Session
/// @see NativeKEMStrategy
/// @see NativeECDHStrategy
/// @since 1.1.0
@Slf4j
public class Server implements Closeable {

    //
    // Constants
    //

    private static final int SELECT_TIMEOUT_MS = 100;
    private static final int HANDSHAKE_CHECK_INTERVAL_MS = 1000;
    private static final int MAX_HANDSHAKE_MSG_SIZE = 16 * 1024;

    //
    // Configuration
    //

    @Getter
    private final ServerConfig config;

    //
    // Network Components
    //

    private ServerSocketChannel serverChannel;
    private Selector selector;

    //
    // Server State
    //

    private final AtomicReference<ServerState> state;
    private final AtomicBoolean running;

    //
    // Session Management
    //

    /// 활성 세션 저장소 (세션 ID -> 세션)
    private final ConcurrentHashMap<String, Session> activeSessions;

    /// 채널별 참여자 매핑 (빠른 조회용)
    private final ConcurrentHashMap<SocketChannel, Participant> channelToParticipant;

    /// 참여자별 세션 매핑
    private final ConcurrentHashMap<String, Session> participantToSession;

    //
    // Security Components
    //

    /// 서버의 장기 키페어 (인증용)
    private SensitiveDataContainer serverPublicKey;
    private SensitiveDataContainer serverSecretKey;

    //
    // Thread Management
    //

    private Thread acceptThread;
    private Thread eventLoopThread;
    private ScheduledExecutorService scheduledExecutor;

    //
    // Event Listeners
    //

    private final CopyOnWriteArrayList<ServerEventListener> eventListeners;

    //
    // Constructor
    //

    /// 지정된 설정으로 서버를 생성합니다.
    ///
    /// @param config 서버 설정
    public Server(@NotNull ServerConfig config) {
        this.config = config;
        this.state = new AtomicReference<>(ServerState.CREATED);
        this.running = new AtomicBoolean(false);

        this.activeSessions = new ConcurrentHashMap<>();
        this.channelToParticipant = new ConcurrentHashMap<>();
        this.participantToSession = new ConcurrentHashMap<>();

        this.eventListeners = new CopyOnWriteArrayList<>();

        log.debug("서버 인스턴스 생성됨: 포트 {}", config.getPort());
    }

    /// 기본 설정으로 서버를 생성합니다.
    ///
    /// @param port 서버 포트
    public Server(int port) {
        this(ServerConfig.builder().port(port).build());
    }

    //
    // Lifecycle Management
    //

    /// 서버를 시작합니다.
    ///
    /// @throws IOException 네트워크 오류 발생 시
    public void start() throws IOException {
        if (!state.compareAndSet(ServerState.CREATED, ServerState.STARTING)) {
            throw new IllegalStateException("서버가 이미 시작되었거나 종료된 상태입니다: " + state.get());
        }

        try {
            initializeServerKeys();
            initializeNetwork();
            initializeThreads();

            running.set(true);
            state.set(ServerState.RUNNING);

            notifyListeners(listener -> listener.onServerStarted(this));
            log.info("서버 시작됨: {}:{}", config.getBindAddress(), config.getPort());
        } catch (Throwable e) {
            state.set(ServerState.FAILED);
            cleanup();
            throw new IOException("서버 시작 실패", e);
        }
    }

    /// 서버를 정상 종료합니다.
    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }

        state.set(ServerState.STOPPING);
        log.info("서버 종료 중...");

        try {
            // 모든 세션 종료
            activeSessions.values().forEach(Session::close);

            // 스레드 종료 대기
            if (scheduledExecutor != null) {
                scheduledExecutor.shutdown();
                scheduledExecutor.awaitTermination(5, TimeUnit.SECONDS);
            }

            // 네트워크 리소스 정리
            cleanup();

            state.set(ServerState.STOPPED);
            notifyListeners(listener -> listener.onServerStopped(this));
            log.info("서버 종료 완료");
        } catch (Exception e) {
            state.set(ServerState.FAILED);
            log.error("서버 종료 중 오류", e);
        }
    }

    @Override
    public void close() {
        stop();
    }

    //
    // Initialization
    //

    private void initializeServerKeys() throws Throwable {
        // 서버 장기 키페어 생성 (기본 KEM 타입 사용)
        KEMType kemType = config.getSessionConfig().getDefaultKemType();
        NativeEntLibAsymmetricKeyStrategy keyStrategy =
                EntLibCryptoRegistry.getKeyStrategy(kemType, NativeEntLibAsymmetricKeyStrategy.class);

        if (keyStrategy instanceof X25519MLKEM768KeyStrategy hybridKey) {
            X25519KeyStrategy x25519KeyStrategy = EntLibCryptoRegistry.getKeyStrategy(KEMType.X25519, X25519KeyStrategy.class);
            MLKEMKeyStrategy mlkem768KeyStrategy = EntLibCryptoRegistry.getKeyStrategy(KEMType.ML_KEM_768, MLKEMKeyStrategy.class);
            hybridKey.setX25519Key(x25519KeyStrategy);
            hybridKey.setMlkem768Key(mlkem768KeyStrategy);
            log.debug("X25519MLKEM768 하이브리드 알고리즘에 따른 개별 스트레티지 주입");
        }

        Pair<SensitiveDataContainer, SensitiveDataContainer> keyPair = keyStrategy.generateKeyPair();
        this.serverPublicKey = keyPair.getFirst();
        this.serverSecretKey = keyPair.getSecond();

        log.debug("서버 키페어 생성 완료: {}", kemType);
    }

    private void initializeNetwork() throws IOException {
        // Selector 생성
        this.selector = Selector.open();

        // 서버 소켓 채널 설정
        this.serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.socket().setReuseAddress(true);

        // 바인드
        SocketAddress bindAddress = new InetSocketAddress(
                config.getBindAddress(),
                config.getPort()
        );
        serverChannel.bind(bindAddress, config.getBacklog());

        // Accept 이벤트 등록
        serverChannel.register(selector, SelectionKey.OP_ACCEPT);

        log.debug("네트워크 초기화 완료: {}", bindAddress);
    }

    private void initializeThreads() {
        // 이벤트 루프 스레드
        this.eventLoopThread = new Thread(this::eventLoop, "TLS-Server-EventLoop");
        eventLoopThread.setDaemon(true);
        eventLoopThread.start();

        // 스케줄러 (타임아웃 체크 등)
        this.scheduledExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "TLS-Server-Scheduler");
            t.setDaemon(true);
            return t;
        });

        // 핸드셰이크 타임아웃 체크
        scheduledExecutor.scheduleAtFixedRate(
                this::checkHandshakeTimeouts,
                HANDSHAKE_CHECK_INTERVAL_MS,
                HANDSHAKE_CHECK_INTERVAL_MS,
                TimeUnit.MILLISECONDS
        );

        // 세션 타임아웃 체크
        scheduledExecutor.scheduleAtFixedRate(
                this::checkSessionTimeouts,
                5000,
                5000,
                TimeUnit.MILLISECONDS
        );

        log.debug("스레드 초기화 완료");
    }

    //
    // Event Loop
    //

    private void eventLoop() {
        log.debug("이벤트 루프 시작");

        while (running.get()) {
            try {
                int readyCount = selector.select(SELECT_TIMEOUT_MS);

                if (readyCount == 0) {
                    continue;
                }

                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = selectedKeys.iterator();

                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();

                    try {
                        if (!key.isValid()) {
                            continue;
                        }

                        if (key.isAcceptable()) {
                            handleAccept(key);
                        } else if (key.isReadable()) {
                            handleRead(key);
                        } else if (key.isWritable()) {
                            handleWrite(key);
                        }
                    } catch (CancelledKeyException e) {
                        log.debug("취소된 키: {}", key);
                    } catch (Exception e) {
                        log.error("키 처리 중 오류", e);
                        closeChannel(key);
                    }
                }
            } catch (ClosedSelectorException e) {
                log.debug("Selector 종료됨");
                break;
            } catch (Exception e) {
                if (running.get()) {
                    log.error("이벤트 루프 오류", e);
                }
            }
        }

        log.debug("이벤트 루프 종료");
    }

    //
    // Connection Handling
    //

    private void handleAccept(SelectionKey key) throws IOException {
        ServerSocketChannel serverCh = (ServerSocketChannel) key.channel();
        SocketChannel clientChannel = serverCh.accept();

        if (clientChannel == null) {
            return;
        }

        clientChannel.configureBlocking(false);

        // 참여자 생성
        String participantId = UUID.randomUUID().toString();
        ParticipantSecurityContext securityContext = new ParticipantSecurityContext(null, null, null);
        Participant participant = new Participant(
                participantId,
                ParticipantRole.RESPONDER,
                clientChannel,
                config.getSessionConfig().getBufferSize(),
                securityContext
        );

        // 채널 매핑
        channelToParticipant.put(clientChannel, participant);

        // 세션 생성 또는 기존 세션에 추가
        Session session = getOrCreateSession();
        try {
            session.addParticipant(participant);
            participantToSession.put(participantId, session);
        } catch (EntLibSessionException e) {
            log.error("참여자 추가 실패", e);
            clientChannel.close();
            channelToParticipant.remove(clientChannel);
            return;
        }

        // READ 이벤트 등록
        clientChannel.register(selector, SelectionKey.OP_READ, participant);

        // 핸드셰이크 시작
        participant.transitionState(ConnectionState.HANDSHAKING);

        notifyListeners(listener -> listener.onClientConnected(this, participant));
        log.debug("새 클라이언트 연결: {} ({})", participantId, clientChannel.getRemoteAddress());
    }

    private void handleRead(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        Participant participant = (Participant) key.attachment();

        if (participant == null) {
            participant = channelToParticipant.get(channel);
        }

        if (participant == null) {
            log.warn("알 수 없는 채널에서 읽기 이벤트");
            closeChannel(key);
            return;
        }

        ByteBuffer buffer = participant.getInboundBuffer();
        int bytesRead;

        try {
            bytesRead = channel.read(buffer);
        } catch (IOException e) {
            log.debug("읽기 오류: {}", e.getMessage());
            closeChannel(key);
            return;
        }

        if (bytesRead == -1) {
            // 연결 종료
            log.debug("클라이언트 연결 종료: {}", participant.getId());
            closeChannel(key);
            return;
        }

        if (bytesRead > 0) {
            buffer.flip();

            ConnectionState state = participant.getState().get();
            if (state == ConnectionState.HANDSHAKING) {
                processHandshake(participant, buffer);
            } else if (state == ConnectionState.ESTABLISHED) {
                processApplicationData(participant, buffer);
            }

            buffer.compact();
        }
    }

    private void handleWrite(SelectionKey key) throws IOException {
        Participant participant = (Participant) key.attachment();
        if (participant == null) {
            key.cancel();
            return;
        }

        // 큐에 있는 데이터를 채널로 밀어넣음
        boolean hasRemaining = participant.flushOutbound();

        // 더 이상 보낼 데이터가 없다면 OP_WRITE 관심 해제 (CPU 점유 방지)
        if (!hasRemaining) {
            key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
        }
    }

    //
    // Handshake Processing
    //

    private void processHandshake(Participant participant, ByteBuffer data) {
        try {
            // 간단한 핸드셰이크 프로토콜 구현
            // 1. 클라이언트 Hello (공개키 포함)
            // 2. 서버 Hello (캡슐화된 공유 비밀)
            // 3. 핸드셰이크 완료

            if (data.remaining() < 1) {
                return;
            }

            byte messageType = data.get();

            switch (messageType) {
                case HandshakeMessage.CLIENT_HELLO -> handleClientHello(participant, data);
                case HandshakeMessage.FINISHED -> handleClientFinished(participant, data);
                default -> log.warn("알 수 없는 핸드셰이크 메시지: {}", messageType);
            }
        } catch (Exception e) {
            log.error("핸드셰이크 처리 오류: {}", participant.getId(), e);
            closeParticipant(participant);
        }
    }

    private void handleClientHello(Participant participant, ByteBuffer data) throws Exception {
        // 클라이언트 공개키 읽기
        // 헤더(길이 필드) 확인 가능한지 체크
        if (data.remaining() < 4) return;

        // 포지션 이동 없이 길이만 확인(PEEK)
        data.mark();
        int keyLength = data.getInt();

        if (keyLength < 0 || keyLength > MAX_HANDSHAKE_MSG_SIZE) {
            throw new EntLibServerSecurityWarningException("핸드셰이크 상한선 초과",
                    "클라이언트 헬로(handleClientHello) 과정에서 키 길이 '" + keyLength + "'를 전달받았지만 방어했습니다!\n" +
                            "\t이는 단순 연산 오류일 수 있지만, 공격자의 악의적 소행일 가능성이 상대적으로 높습니다. 공격자는 다음의 공격을 시도했을 수 있습니다.\n" +
                            "\t\t1. '" + Integer.MAX_VALUE + "' 이상의 데이터를 전송하여 2GB 이상의 (바이트) 배열을 할당하려 시도합니다.\n" +
                            "\t\t2. 그럼, 서버 측은 수십 개의 연결만으로도 힙 메모리가 고갈되어 `OutOfMemoryError`로 서버가 다운될 수 있습니다.\n" +
                            "\t예외적으로 전달받은 값이 '0' 미만일 수 있습니다만, 이 경우는 사실 말이 안 됩니다.\n" +
                            "\t우선 어찌됐던 이 시도를 막아내었지만, 추가적인 보안 조치가 필요할 수 있습니다."
            );
        }

        // 전체 바디가 도착했는지 확인
        if (data.remaining() < keyLength) {
            data.reset(); // 포지션 원복
            return; // 다음 패킷 기다림
        }

        // 데이터 읽기(COMMIT)
        byte[] clientPublicKeyBytes = new byte[keyLength];
        data.get(clientPublicKeyBytes);

        // 공개키 저장
        SensitiveDataContainer clientPublicKey = new SensitiveDataContainer(keyLength);
        clientPublicKey.getMemorySegment().asByteBuffer().put(clientPublicKeyBytes);

        // KEM 캡슐화 수행
        KEMType kemType = config.getSessionConfig().getDefaultKemType();
        NativeKEMStrategy kemStrategy = EntLibCryptoRegistry.getAlgStrategy(kemType, NativeKEMStrategy.class);

        final SensitiveDataContainer encapResult = kemStrategy.encapsulate(clientPublicKey);

        // 공유 비밀 추출 및 세션 키 설정
        // encapResult는 (sharedSecret, ciphertext)를 포함
        // TODO: 실제 세션 키 설정 로직

        // 서버 Hello 응답 전송
        sendServerHello(participant, encapResult);

        log.debug("Client Hello 처리 완료: {}", participant.getId());
    }

    private void sendServerHello(Participant participant, SensitiveDataContainer encapResult) throws IOException {
        SocketChannel channel = participant.getChannel();

        // 메시지 구성: [타입(1)] + [서버 공개키 길이(4)] + [서버 공개키] + [캡슐화 결과 길이(4)] + [캡슐화 결과]
        int serverPkLength = (int) serverPublicKey.getMemorySegment().byteSize();
        int encapLength = (int) encapResult.getMemorySegment().byteSize();

        ByteBuffer response = ByteBuffer.allocate(1 + 4 + serverPkLength + 4 + encapLength);
        response.put(HandshakeMessage.SERVER_HELLO);
        response.putInt(serverPkLength);

        ByteBuffer pkBuffer = serverPublicKey.getMemorySegment().asByteBuffer();
        response.put(pkBuffer);

        response.putInt(encapLength);
        ByteBuffer encapBuffer = encapResult.getMemorySegment().asByteBuffer();
        response.put(encapBuffer);

        response.flip();
        channel.write(response);

        log.debug("Server Hello 전송: {}", participant.getId());
    }

    private void handleClientFinished(Participant participant, ByteBuffer data) {
        // 핸드셰이크 완료 처리
        participant.transitionState(ConnectionState.ESTABLISHED);

        notifyListeners(listener -> listener.onHandshakeCompleted(this, participant));
        log.info("핸드셰이크 완료: {}", participant.getId());
    }

    //
    // Application Data Processing
    //

    private void processApplicationData(Participant participant, ByteBuffer data) {
        // 암호화된 애플리케이션 데이터 처리
        // TODO: 실제 복호화 및 데이터 처리 로직

        notifyListeners(listener -> listener.onDataReceived(this, participant, data));
    }

    //
    // Session Management
    //

    private Session getOrCreateSession() {
        // 단일 세션 모드 (설정에 따라 다중 세션 지원 가능)
        if (config.isSingleSessionMode() && !activeSessions.isEmpty()) {
            return activeSessions.values().iterator().next();
        }

        Session session = Session.create(config.getSessionConfig());
        try {
            session.activate();
        } catch (EntLibSessionException e) {
            log.error("세션 활성화 실패", e);
        }
        activeSessions.put(session.getSessionId(), session);
        return session;
    }

    /// 특정 세션을 조회합니다.
    ///
    /// @param sessionId 세션 ID
    /// @return 세션 (없으면 null)
    @Nullable
    public Session getSession(@NotNull String sessionId) {
        return activeSessions.get(sessionId);
    }

    /// 모든 활성 세션을 반환합니다.
    ///
    /// @return 활성 세션 맵 (불변)
    @NotNull
    public Map<String, Session> getActiveSessions() {
        return Map.copyOf(activeSessions);
    }

    /// 현재 연결된 클라이언트 수를 반환합니다.
    ///
    /// @return 연결된 클라이언트 수
    public int getConnectedClientCount() {
        return channelToParticipant.size();
    }

    //
    // Timeout Management
    //

    private void checkHandshakeTimeouts() {
        long now = System.currentTimeMillis();
        long timeout = config.getSessionConfig().getHandshakeTimeoutMillis();

        channelToParticipant.forEach((_, participant) -> {
            if (participant.getState().get() == ConnectionState.HANDSHAKING) {
                long elapsed = now - participant.getConnectedAt();
                if (elapsed > timeout) {
                    log.warn("핸드셰이크 타임아웃: {}", participant.getId());
                    closeParticipant(participant);
                }
            }
        });
    }

    private void checkSessionTimeouts() {
        long now = System.currentTimeMillis();

        activeSessions.forEach((id, session) -> {
            // 세션 전체 타임아웃
            if (session.getDuration() > session.getConfig().getSessionTimeoutMillis()) {
                log.info("세션 타임아웃 (전체): {}", id);
                session.close();
                activeSessions.remove(id);
                return;
            }

            // 유휴 타임아웃
            if (session.getIdleTime() > session.getConfig().getIdleTimeoutMillis()) {
                log.info("세션 타임아웃 (유휴): {}", id);
                session.close();
                activeSessions.remove(id);
            }
        });
    }

    //
    // Cleanup
    //

    private void closeChannel(SelectionKey key) {
        try {
            SocketChannel channel = (SocketChannel) key.channel();
            Participant participant = channelToParticipant.remove(channel);

            if (participant != null) {
                closeParticipant(participant);
            }

            key.cancel();
            channel.close();
        } catch (IOException e) {
            log.debug("채널 종료 오류", e);
        }
    }

    private void closeParticipant(Participant participant) {
        participant.transitionState(ConnectionState.CLOSED);
        channelToParticipant.remove(participant.getChannel());

        Session session = participantToSession.remove(participant.getId());
        if (session != null) {
            session.removeParticipant(participant.getId());
        }

        try {
            participant.getChannel().close();
        } catch (IOException e) {
            log.debug("참여자 채널 종료 오류", e);
        }

        notifyListeners(listener -> listener.onClientDisconnected(this, participant));
    }

    private void cleanup() {
        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close();
            }
            if (selector != null && selector.isOpen()) {
                selector.close();
            }

            // 키 정리
            if (serverSecretKey != null) {
                serverSecretKey.close();
            }
            if (serverPublicKey != null) {
                serverPublicKey.close();
            }

        } catch (IOException e) {
            log.error("리소스 정리 오류", e);
        }
    }

    //
    // Data Transmission
    //

    /// 특정 참여자에게 데이터를 전송합니다.
    /// 데이터는 즉시 전송을 시도하며, 소켓 버퍼가 가득 찬 경우
    /// 참여자의 OutboundQueue에 적재되고 OP_WRITE 이벤트를 통해 비동기로 처리됩니다.
    ///
    /// @param participant 대상 참여자
    /// @param data        전송할 데이터
    /// @throws IOException 전송 오류 시
    public void send(@NotNull Participant participant, @NotNull ByteBuffer data) throws IOException, EntLibServerIllegalStateException, EntLibSecureIllegalArgumentException, EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException {
        if (participant.getState().get() != ConnectionState.ESTABLISHED) {
            throw new EntLibServerIllegalStateException("연결이 설정되지 않은 참여자입니다!");
        }

        {
            final byte[] plaintext = new byte[data.remaining()];
            long writeSequence = participant.getParticipantSecurityContext().getNextWriteSequence();
            BlockCipherStrategy aes256GCM = EntLibCryptoRegistry.getAlgStrategy(CipherType.AES_256, BlockCipherStrategy.class)
                    .setMode(Mode.AEAD_GCM)
                    .setPadding(Padding.NO);
            aes256GCM.iv(CipherStrategy.calculateNonce(SensitiveDataContainer.generateSafeRandomBytes(12), writeSequence));
            SensitiveDataContainer enc = aes256GCM.encrypt(
                    participant.getParticipantSecurityContext().getSessionKey(),
                    data.get(plaintext),
                    false);
            participant.enqueueMessage(enc.getSegmentDataToByteBuffer());
        } // 암호화 및 enqueue

        boolean hasRemaining = participant.flushOutbound();

        if (hasRemaining) {
            SelectionKey key = participant.getChannel().keyFor(selector);
            if (key != null && key.isValid()) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                selector.wakeup();
            }
        }
    }

    /// 특정 세션의 모든 참여자에게 데이터를 브로드캐스트합니다.
    ///
    /// @param session 대상 세션
    /// @param data    전송할 데이터
    public void broadcast(@NotNull Session session, @NotNull ByteBuffer data) {
        session.getAllParticipants().forEach(participant -> {
            try {
                if (participant.isSecure()) {
                    ByteBuffer copy = data.duplicate();
                    send(participant, copy);
                }
            } catch (EntLibSecureIllegalArgumentException | EntLibCryptoCipherProcessException |
                     EntLibSecureIllegalStateException | EntLibServerIllegalStateException | IOException e) {
                log.error("브로드캐스트 전송 오류: {}", participant.getId(), e);
            }
        });
    }

    //
    // Event Listener Management
    //

    /// 서버 이벤트 리스너를 등록합니다.
    ///
    /// @param listener 등록할 리스너
    public void addEventListener(@NotNull ServerEventListener listener) {
        eventListeners.add(listener);
    }

    /// 서버 이벤트 리스너를 제거합니다.
    ///
    /// @param listener 제거할 리스너
    public void removeEventListener(@NotNull ServerEventListener listener) {
        eventListeners.remove(listener);
    }

    private void notifyListeners(java.util.function.Consumer<ServerEventListener> action) {
        for (ServerEventListener listener : eventListeners) {
            try {
                action.accept(listener);
            } catch (Exception e) {
                log.error("리스너 실행 오류", e);
            }
        }
    }

    //
    // Status Methods
    //

    /// 서버가 실행 중인지 확인합니다.
    ///
    /// @return 실행 중 여부
    public boolean isRunning() {
        return running.get() && state.get() == ServerState.RUNNING;
    }

    /// 서버 상태를 반환합니다.
    ///
    /// @return 서버 상태
    @NotNull
    public ServerState getState() {
        return state.get();
    }

    @Override
    public String toString() {
        return "Server{" +
                "port=" + config.getPort() +
                ", state=" + state.get() +
                ", sessions=" + activeSessions.size() +
                ", clients=" + channelToParticipant.size() +
                '}';
    }
}
