/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.session.EntLibSessionIllegalStateException;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/// 세션 수준의 보안 컨텍스트를 관리하는 클래스입니다.
///
/// 이 클래스는 세션 전체에 적용되는 암호화 설정과 키 자료를 관리합니다.
/// 개별 참여자의 [ParticipantSecurityContext]와 구분되며, 그룹 통신 시 공통으로
/// 사용되는 보안 파라미터를 포함합니다.
///
/// ## 주요 구성 요소
/// - 세션 마스터 키 (그룹 암호화용)
/// - 협상된 암호화 알고리즘
/// - 세션 수준 시퀀스 카운터
///
/// @author Q. T. Felix
/// @see Session
/// @see ParticipantSecurityContext
/// @since 1.1.0
@Slf4j
@Getter
public class SessionSecurityContext {

    /// 세션 마스터 키 (그룹 브로드캐스트 암호화용)
    private volatile SensitiveDataContainer sessionMasterKey;

    /// 세션 마스터 키 파생용 솔트
    private volatile SensitiveDataContainer masterKeySalt;

    /// 협상된 KEM 알고리즘
    private volatile KEMType negotiatedKemType;

    /// 협상된 서명 알고리즘
    private volatile SignatureType negotiatedSignatureType;

    /// 클래식 ECDH 사용 여부 (하이브리드 모드)
    private volatile boolean classicEcdhEnabled;

    /// 세션 수준 메시지 카운터 (리플레이 공격 방지)
    private final AtomicLong sessionMessageCounter;

    /// 마지막 키 갱신 시각
    private volatile long lastKeyRotationAt;

    /// 키 갱신 주기 (밀리초, 0이면 자동 갱신 안함)
    private volatile long keyRotationIntervalMillis;

    /// 컨텍스트 초기화 완료 여부
    private final AtomicBoolean initialized;

    /// 컨텍스트 정리 완료 여부
    private final AtomicBoolean cleared;

    public SessionSecurityContext() {
        this.sessionMessageCounter = new AtomicLong(0);
        this.initialized = new AtomicBoolean(false);
        this.cleared = new AtomicBoolean(false);
        this.lastKeyRotationAt = System.currentTimeMillis();
        this.keyRotationIntervalMillis = 0;
    }

    /// 세션 보안 컨텍스트를 초기화합니다.
    ///
    /// @param masterKey     세션 마스터 키
    /// @param salt          마스터 키 솔트
    /// @param kemType       KEM 알고리즘
    /// @param signatureType 서명 알고리즘
    /// @param useClassicEcdh 클래식 ECDH 사용 여부
    public void initialize(
            @NotNull SensitiveDataContainer masterKey,
            @Nullable SensitiveDataContainer salt,
            @NotNull KEMType kemType,
            @NotNull SignatureType signatureType,
            boolean useClassicEcdh
    ) throws EntLibSessionIllegalStateException {
        if (cleared.get()) {
            throw new EntLibSessionIllegalStateException("정리된 보안 컨텍스트는 초기화할 수 없습니다.");
        }

        this.sessionMasterKey = masterKey;
        this.masterKeySalt = salt;
        this.negotiatedKemType = kemType;
        this.negotiatedSignatureType = signatureType;
        this.classicEcdhEnabled = useClassicEcdh;
        this.lastKeyRotationAt = System.currentTimeMillis();

        initialized.set(true);
        log.debug("세션 보안 컨텍스트 초기화됨: KEM={}, Sig={}, ClassicECDH={}",
                kemType, signatureType, useClassicEcdh);
    }

    /// 다음 세션 메시지 카운터 값을 반환하고 증가시킵니다.
    ///
    /// @return 현재 메시지 카운터 값
    public long getNextMessageCounter() {
        return sessionMessageCounter.getAndIncrement();
    }

    /// 현재 세션 메시지 카운터 값을 반환합니다.
    ///
    /// @return 현재 메시지 카운터 값
    public long getCurrentMessageCounter() {
        return sessionMessageCounter.get();
    }

    /// 키 갱신이 필요한지 확인합니다.
    ///
    /// @return 키 갱신 필요 여부
    public boolean needsKeyRotation() {
        if (keyRotationIntervalMillis <= 0) {
            return false;
        }
        return System.currentTimeMillis() - lastKeyRotationAt >= keyRotationIntervalMillis;
    }

    /// 세션 마스터 키를 갱신합니다.
    ///
    /// @param newMasterKey 새 마스터 키
    /// @param newSalt      새 솔트 (선택적)
    public void rotateKey(@NotNull SensitiveDataContainer newMasterKey,
                          @Nullable SensitiveDataContainer newSalt) throws EntLibSessionIllegalStateException {
        if (!initialized.get())
            throw new EntLibSessionIllegalStateException("초기화되지 않은 보안 컨텍스트입니다.");
        if (cleared.get())
            throw new EntLibSessionIllegalStateException("정리된 보안 컨텍스트입니다.");

        // 기존 키 안전하게 정리
        SensitiveDataContainer oldKey = this.sessionMasterKey;
        SensitiveDataContainer oldSalt = this.masterKeySalt;

        this.sessionMasterKey = newMasterKey;
        this.masterKeySalt = newSalt;
        this.lastKeyRotationAt = System.currentTimeMillis();

        // 기존 키 안전하게 삭제
        if (oldKey != null)
            oldKey.close();
        if (oldSalt != null)
            oldSalt.close();

        log.debug("세션 마스터 키 갱신됨");
    }

    /// 키 갱신 주기를 설정합니다.
    ///
    /// @param intervalMillis 갱신 주기 (밀리초, 0이면 자동 갱신 안함)
    public void setKeyRotationInterval(long intervalMillis) {
        this.keyRotationIntervalMillis = intervalMillis;
    }

    /// 보안 컨텍스트가 초기화되었는지 확인합니다.
    ///
    /// @return 초기화 완료 여부
    public boolean isInitialized() {
        return initialized.get();
    }

    /// 보안 컨텍스트가 정리되었는지 확인합니다.
    ///
    /// @return 정리 완료 여부
    public boolean isCleared() {
        return cleared.get();
    }

    /// 보안 컨텍스트의 모든 민감한 데이터를 안전하게 정리합니다.
    ///
    /// 이 메소드 호출 후에는 컨텍스트를 더 이상 사용할 수 없습니다.
    public void clear() {
        if (cleared.compareAndSet(false, true)) {
            if (sessionMasterKey != null) {
                sessionMasterKey.close();
                sessionMasterKey = null;
            }
            if (masterKeySalt != null) {
                masterKeySalt.close();
                masterKeySalt = null;
            }

            sessionMessageCounter.set(0);
            initialized.set(false);

            log.debug("세션 보안 컨텍스트 정리됨");
        }
    }

    /// 보안 컨텍스트의 요약 정보를 반환합니다.
    ///
    /// @return 요약 문자열 (민감한 정보 제외)
    @Override
    public String toString() {
        return "SessionSecurityContext{" +
                "initialized=" + initialized.get() +
                ", cleared=" + cleared.get() +
                ", kemType=" + negotiatedKemType +
                ", signatureType=" + negotiatedSignatureType +
                ", classicEcdh=" + classicEcdhEnabled +
                ", messageCounter=" + sessionMessageCounter.get() +
                '}';
    }
}
