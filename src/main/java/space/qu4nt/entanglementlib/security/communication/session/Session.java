/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.session.EntLibSessionException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Predicate;

/// 보안 통신 세션을 관리하는 클래스입니다.
///
/// 세션은 여러 참여자들이 보안 통신을 수행할 수 있는 논리적 컨텍스트를 제공합니다.
/// 각 세션은 고유한 식별자, 세션 수준의 보안 컨텍스트, 그리고 참여자 목록을 관리합니다.
///
/// ## 주요 기능
/// - 다수의 참여자 관리 (추가, 제거, 조회)
/// - 세션 수준 보안 컨텍스트 관리
/// - 세션 생명주기 관리 (생성, 활성, 종료)
/// - 유연한 세션 설정 (최대 참여자 수, 타임아웃 등)
/// - 스레드 안전 연산
///
/// ## 사용 예시
/// ```java
/// SessionConfig config = SessionConfig.builder()
///     .maxParticipants(10)
///     .sessionTimeout(Duration.ofMinutes(30))
///     .build();
///
/// Session session = Session.create(config);
/// session.addParticipant(participant);
/// ```
///
/// @author Q. T. Felix
/// @see Participant
/// @see ParticipantSecurityContext
/// @see SessionConfig
/// @since 1.1.0
@Slf4j
@Getter
public class Session {

    /// 세션 고유 식별자
    private final String sessionId;

    /// 세션 생성 시각 (Unix timestamp milliseconds)
    private final long createdAt;

    /// 세션 설정
    private final SessionConfig config;

    /// 세션 수준 보안 컨텍스트 (그룹 키, 공통 암호화 설정 등)
    private volatile SessionSecurityContext sessionSecurityContext;

    /// 세션 상태
    private final AtomicReference<SessionState> state;

    /// 참여자 저장소 (ID -> Participant)
    private final ConcurrentHashMap<String, Participant> participants;

    /// 역할별 참여자 인덱스 (빠른 역할 기반 조회용)
    private final ConcurrentHashMap<ParticipantRole, Set<String>> participantsByRole;

    /// 참여자 목록 수정을 위한 읽기-쓰기 락
    private final ReentrantReadWriteLock participantsLock;

    /// 세션 이벤트 리스너
    private final List<SessionEventListener> eventListeners;

    /// 마지막 활동 시각
    private volatile long lastActivityAt;

    //
    // factory - start
    //

    private Session(String sessionId, SessionConfig config) {
        this.sessionId = sessionId;
        this.createdAt = System.currentTimeMillis();
        this.lastActivityAt = this.createdAt;
        this.config = config;

        this.state = new AtomicReference<>(SessionState.CREATED);
        this.participants = new ConcurrentHashMap<>();
        this.participantsByRole = new ConcurrentHashMap<>();
        this.participantsLock = new ReentrantReadWriteLock();
        // 순회 시 락이 필요 없는 CopyOnWrite 병렬 컬렉션 사용 변경
        this.eventListeners = new CopyOnWriteArrayList<>();

        log.debug("세션 생성됨: {}", sessionId);
    }

    /// 기본 설정으로 새 세션을 생성합니다.
    ///
    /// @return 새로 생성된 세션
    public static Session create() {
        return create(SessionConfig.defaults());
    }

    /// 지정된 설정으로 새 세션을 생성합니다.
    ///
    /// @param config 세션 설정
    /// @return 새로 생성된 세션
    public static Session create(@NotNull SessionConfig config) {
        String sessionId = generateSessionId();
        return new Session(sessionId, config);
    }

    /// 지정된 ID와 설정으로 새 세션을 생성합니다.
    ///
    /// @param sessionId 세션 ID
    /// @param config    세션 설정
    /// @return 새로 생성된 세션
    public static Session create(@NotNull String sessionId, @NotNull SessionConfig config) {
        return new Session(sessionId, config);
    }

    private static String generateSessionId() {
        return UUID.randomUUID().toString();
    }

    //
    // factory - end
    //

    //
    // Participants - start
    //

    /// 세션에 참여자를 추가합니다.
    ///
    /// @param participant 추가할 참여자
    /// @return 추가 성공 여부
    /// @throws EntLibSessionException 세션이 활성 상태가 아니거나 최대 참여자 수 초과 시
    public boolean addParticipant(@NotNull Participant participant) throws EntLibSessionException {
        validateSessionActive();

        participantsLock.writeLock().lock();
        try {
            // 최대 참여자 수 확인
            if (config.getMaxParticipants() > 0 &&
                    participants.size() >= config.getMaxParticipants()) {
                throw new EntLibSessionException("최대 참여자 수를 초과했습니다: " + config.getMaxParticipants());
            }

            // 중복 확인
            if (participants.containsKey(participant.getId())) {
                log.warn("이미 존재하는 참여자 ID: {}", participant.getId());
                return false;
            }

            // 참여자 추가
            participants.put(participant.getId(), participant);

            // 역할별 인덱스 업데이트
            participantsByRole
                    .computeIfAbsent(participant.getRole(), k -> ConcurrentHashMap.newKeySet())
                    .add(participant.getId());

            updateActivity();
            notifyListeners(listener -> listener.onParticipantJoined(this, participant));

            log.debug("참여자 추가됨: {} (역할: {})", participant.getId(), participant.getRole());
            return true;
        } finally {
            participantsLock.writeLock().unlock();
        }
    }

    /// 세션에서 참여자를 제거합니다.
    ///
    /// @param participantId 제거할 참여자 ID
    /// @return 제거된 참여자 (없으면 null)
    @Nullable
    public Participant removeParticipant(@NotNull String participantId) {
        participantsLock.writeLock().lock();
        try {
            Participant removed = participants.remove(participantId);
            if (removed != null) {
                // 역할별 인덱스에서도 제거
                Set<String> roleSet = participantsByRole.get(removed.getRole());
                if (roleSet != null) {
                    roleSet.remove(participantId);
                }

                updateActivity();
                notifyListeners(listener -> listener.onParticipantLeft(this, removed));

                log.debug("참여자 제거됨: {}", participantId);
            }
            return removed;
        } finally {
            participantsLock.writeLock().unlock();
        }
    }

    /// ID로 참여자를 조회합니다.
    ///
    /// @param participantId 참여자 ID
    /// @return 참여자 (없으면 null)
    @Nullable
    public Participant getParticipant(@NotNull String participantId) {
        return participants.get(participantId);
    }

    /// 특정 역할의 모든 참여자를 조회합니다.
    ///
    /// @param role 참여자 역할
    /// @return 해당 역할의 참여자 목록 (불변)
    @NotNull
    public List<Participant> getParticipantsByRole(@NotNull ParticipantRole role) {
        participantsLock.readLock().lock();
        try {
            Set<String> ids = participantsByRole.get(role);
            if (ids == null || ids.isEmpty()) {
                return Collections.emptyList();
            }
            return ids.stream()
                    .map(participants::get)
                    .filter(Objects::nonNull)
                    .toList();
        } finally {
            participantsLock.readLock().unlock();
        }
    }

    /// 조건에 맞는 참여자들을 조회합니다.
    ///
    /// @param predicate 필터 조건
    /// @return 조건에 맞는 참여자 목록
    @NotNull
    public List<Participant> findParticipants(@NotNull Predicate<Participant> predicate) {
        participantsLock.readLock().lock();
        try {
            return participants.values().stream()
                    .filter(predicate)
                    .toList();
        } finally {
            participantsLock.readLock().unlock();
        }
    }

    /// 모든 참여자 목록을 반환합니다.
    ///
    /// @return 모든 참여자 목록 (불변)
    @NotNull
    public Collection<Participant> getAllParticipants() {
        return Collections.unmodifiableCollection(participants.values());
    }

    /// 현재 참여자 수를 반환합니다.
    ///
    /// @return 참여자 수
    public int getParticipantCount() {
        return participants.size();
    }

    /// 세션에 참여자가 있는지 확인합니다.
    ///
    /// @param participantId 참여자 ID
    /// @return 존재 여부
    public boolean hasParticipant(@NotNull String participantId) {
        return participants.containsKey(participantId);
    }

    //
    // Participants - end
    //

    //
    // Session Status - start
    //

    /// 세션을 활성화합니다.
    ///
    /// @throws EntLibSessionException 세션이 이미 종료된 경우
    public void activate() throws EntLibSessionException {
        SessionState current = state.get();
        if (current == SessionState.CLOSED || current == SessionState.TERMINATED) {
            throw new EntLibSessionException("종료된 세션은 활성화할 수 없습니다.");
        }

        if (state.compareAndSet(SessionState.CREATED, SessionState.ACTIVE) ||
                state.compareAndSet(SessionState.SUSPENDED, SessionState.ACTIVE)) {
            updateActivity();
            notifyListeners(listener -> listener.onSessionStateChanged(this, current, SessionState.ACTIVE));
            log.info("세션 활성화됨: {}", sessionId);
        }
    }

    /// 세션을 일시 중단합니다.
    public void suspend() {
        SessionState current = state.get();
        if (current == SessionState.ACTIVE) {
            if (state.compareAndSet(SessionState.ACTIVE, SessionState.SUSPENDED)) {
                notifyListeners(listener -> listener.onSessionStateChanged(this, current, SessionState.SUSPENDED));
                log.info("세션 일시 중단됨: {}", sessionId);
            }
        }
    }

    /// 세션을 정상 종료합니다.
    /// 모든 참여자에게 종료를 알리고 리소스를 정리합니다.
    public void close() {
        SessionState current = state.get();
        if (current == SessionState.CLOSED || current == SessionState.TERMINATED) {
            return;
        }

        if (state.compareAndSet(current, SessionState.CLOSING)) {
            try {
                notifyListeners(listener -> listener.onSessionClosing(this));

                // 방어적 복사 로컬 리스트
                List<Participant> participantsToClose;

                // lock scope 최소화 -> 내부 컬렉션 상태만 조작
                participantsLock.writeLock().lock();
                try {
                    // 스냅샷 생성
                    participantsToClose = new ArrayList<>(participants.values());
                    participants.clear();
                    participantsByRole.clear();
                } finally {
                    participantsLock.writeLock().unlock();
                }

                // 락이 해제된 안전한 상태에서 외부 메소드(alien method) 호출
                participantsToClose.forEach(p ->
                        p.transitionState(ConnectionState.CLOSING)
                );

                if (sessionSecurityContext != null) {
                    sessionSecurityContext.clear();
                }

                state.set(SessionState.CLOSED);
                notifyListeners(listener -> listener.onSessionClosed(this));
                log.info("세션 종료됨: {}", sessionId);
            } catch (Exception e) {
                state.set(SessionState.TERMINATED);
                log.error("세션 종료 중 오류 발생: {}", sessionId, e);
            }
        }
    }

    /// 세션을 강제 종료합니다.
    public void terminate() {
        SessionState current = state.get();
        if (current != SessionState.TERMINATED) {
            state.set(SessionState.TERMINATED);

            participantsLock.writeLock().lock();
            try {
                participants.clear();
                participantsByRole.clear();
            } finally {
                participantsLock.writeLock().unlock();
            }

            if (sessionSecurityContext != null) {
                sessionSecurityContext.clear();
            }

            notifyListeners(listener -> listener.onSessionTerminated(this));
            log.warn("세션 강제 종료됨: {}", sessionId);
        }
    }

    /// 세션이 활성 상태인지 확인합니다.
    ///
    /// @return 활성 상태 여부
    public boolean isActive() {
        return state.get() == SessionState.ACTIVE;
    }

    /// 세션이 종료되었는지 확인합니다.
    ///
    /// @return 종료 여부
    public boolean isClosed() {
        SessionState current = state.get();
        return current == SessionState.CLOSED || current == SessionState.TERMINATED;
    }

    //
    // Session Status - end
    //

    //
    // SecurityContext - start
    //

    /// 세션 수준 보안 컨텍스트를 설정합니다.
    ///
    /// @param securityContext 설정할 보안 컨텍스트
    public void setSessionSecurityContext(@NotNull SessionSecurityContext securityContext) {
        this.sessionSecurityContext = securityContext;
        updateActivity();
        log.debug("세션 보안 컨텍스트 설정됨: {}", sessionId);
    }

    /// 세션의 모든 참여자가 보안 연결 상태인지 확인합니다.
    ///
    /// @return 모든 참여자가 보안 연결 상태면 true
    public boolean isFullySecure() {
        if (participants.isEmpty()) {
            return false;
        }
        return participants.values().stream().allMatch(Participant::isSecure);
    }

    //
    // SecurityContext - end
    //

    //
    // EventListener - start
    //

    /// 세션 이벤트 리스너를 등록합니다.
    ///
    /// @param listener 등록할 리스너
    public void addEventListener(@NotNull SessionEventListener listener) {
        eventListeners.add(listener);
    }

    /// 세션 이벤트 리스너를 제거합니다.
    ///
    /// @param listener 제거할 리스너
    public void removeEventListener(@NotNull SessionEventListener listener) {
        eventListeners.remove(listener);
    }

    private void notifyListeners(Consumer<SessionEventListener> action) {
        for (SessionEventListener listener : eventListeners) {
            try {
                action.accept(listener);
            } catch (Exception e) {
                log.error("이벤트 리스너 실행 중 오류", e);
            }
        }
    }

    //
    // EventListener - end
    //

    //
    // Utility - start
    //

    private void validateSessionActive() throws EntLibSessionException {
        SessionState current = state.get();
        if (current != SessionState.ACTIVE && current != SessionState.CREATED) {
            throw new EntLibSessionException("세션이 활성 상태가 아닙니다: " + current);
        }
    }

    private void updateActivity() {
        this.lastActivityAt = System.currentTimeMillis();
    }

    /// 세션 유휴 시간을 반환합니다.
    ///
    /// @return 마지막 활동 이후 경과 시간 (밀리초)
    public long getIdleTime() {
        return System.currentTimeMillis() - lastActivityAt;
    }

    /// 세션 지속 시간을 반환합니다.
    ///
    /// @return 세션 생성 이후 경과 시간 (밀리초)
    public long getDuration() {
        return System.currentTimeMillis() - createdAt;
    }

    //
    // Utility - end
    //

    @Override
    public String toString() {
        return "Session{" +
                "sessionId='" + sessionId + '\'' +
                ", state=" + state.get() +
                ", participants=" + participants.size() +
                ", createdAt=" + createdAt +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Session session = (Session) o;
        return Objects.equals(sessionId, session.sessionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId);
    }
}
