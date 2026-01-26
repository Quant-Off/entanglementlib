/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

import lombok.Getter;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;

/// 세션 참여자는 반드시 다음 세 가지의 핵심 요소를 포함해야 합니다.
///
/// 1. 식별자(identity) - 누구인가?
/// 2. 연결 방법(transport) - 어떻게 왔는가?
/// 3. 보안 방법(security) - 어떻게 암호화되나?
///
/// 이 클래스는 이러한 정보를 안고 연결될 '참여자'의 기본 스키마를
/// 제공하며, 논블로킹 I/O를 위한 인바운드/아웃바운드 버퍼링을 지원합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
@Getter
public class Participant {

    // 식별자 정보
    private final String id;
    private final ParticipantRole role;
    private final long connectedAt;

    // 네트워크 컨텍스트
    private final SocketChannel channel;
    private final SocketAddress remoteAddress;

    // TCP 분할(Fragmentation) 및 부분 쓰기(Partial Write) 처리를 위한 버퍼
    // 대형 PQC 키 교환 시 필수적입니다.
    private final ByteBuffer inboundBuffer;

    // 스레드 안전성을 위해 ConcurrentLinkedQueue 사용 (App스레드 -> IO스레드)
    private final Queue<ByteBuffer> outboundQueue;

    // 보안 컨텍스트
    private final ParticipantSecurityContext participantSecurityContext;

    // 참여자 연결 상태 매니지먼트
    private final AtomicReference<ConnectionState> state;

    public Participant(String id, ParticipantRole role, SocketChannel channel, int bufferSize, ParticipantSecurityContext participantSecurityContext) {
        this.id = id;
        this.role = role;
        this.channel = channel;
        this.remoteAddress = channel.socket().getRemoteSocketAddress();
        this.connectedAt = System.currentTimeMillis();

        // zero-copy 성능을 위한 직접 버퍼 할당
        this.inboundBuffer = ByteBuffer.allocateDirect(bufferSize);

        // ArrayDeque는 스레드 안전하지 않으므로 ConcurrentLinkedQueue로 변경
        this.outboundQueue = new ConcurrentLinkedQueue<>();

        this.participantSecurityContext = participantSecurityContext;
        this.state = new AtomicReference<>(ConnectionState.CONNECTING);
    }

    public boolean isSecure() {
        return state.get() == ConnectionState.ESTABLISHED;
    }

    public void transitionState(ConnectionState newState) {
        // TODO: 상태 전이 검증 로직 (예: CLOSED 상태에서는 변경 불가 등)
        this.state.set(newState);
    }

    /// 전송할 데이터를 아웃바운드 큐에 등록합니다.
    /// 실제 전송은 Selector의 OP_WRITE 이벤트 루프에서 처리됩니다.
    ///
    /// @param data 전송할 데이터가 담긴 ByteBuffer
    public void enqueueMessage(ByteBuffer data) {
        if (data != null && data.hasRemaining()) {
            outboundQueue.offer(data);
        }
    }

    /// 아웃바운드 큐에 쌓인 데이터를 채널로 전송을 시도합니다.
    /// 논블로킹 모드이므로 데이터가 전부 전송되지 않을 수 있습니다.
    ///
    /// @return true면 아직 보낼 데이터가 남음(OP_WRITE 유지 필요),
    ///         false면 큐가 비었음(OP_WRITE 해제 가능)
    /// @throws IOException 채널 쓰기 중 오류 발생 시
    public boolean flushOutbound() throws IOException {
        ByteBuffer buffer;

        // 큐의 헤드(가장 먼저 들어온 데이터)를 확인
        while ((buffer = outboundQueue.peek()) != null) {

            // 채널에 쓰기 시도
            channel.write(buffer);

            // 1. Partial Write 발생: 채널 버퍼가 꽉 차서 데이터를 다 못 씀
            if (buffer.hasRemaining()) {
                // 루프 종료. 다음 OP_WRITE 이벤트 때 남은 부분부터 이어서 보냄
                return true;
            }

            // 2. Full Write 완료: 현재 버퍼를 다 썼으므로 큐에서 제거
            outboundQueue.poll();
        }

        // 큐가 비었음
        return false;
    }

    /// 아웃바운드 큐에 데이터가 있는지 확인합니다.
    public boolean hasOutboundData() {
        return !outboundQueue.isEmpty();
    }

    /// 리소스 정리 시 호출하여 메모리 누수를 방지합니다.
    public void cleanup() {
        outboundQueue.clear();
        // DirectBuffer는 GC가 처리하지만, 필요한 경우 명시적 해제 로직 추가 가능
    }
}