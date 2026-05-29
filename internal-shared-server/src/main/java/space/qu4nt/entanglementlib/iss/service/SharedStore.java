/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.service;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.iss.exception.IssException;
import space.qu4nt.entanglementlib.iss.internal.SdcBytes;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/// 폐쇄망 노드들이 공유하는 인메모리 키-값 저장소입니다.
///
/// # Security Note
/// 값은 잠금된 off-heap [SensitiveDataContainer]에 보관되어 GC `heap`에 상주하지 않으며, 삭제 및
/// 서버 종료 시 소거(zeroize)됩니다. 여러 연결 스레드가 동시에 접근하므로 모든 연산을 단일 락으로
/// 직렬화합니다. 교차 스레드 컨테이너 접근을 위해 보안 모듈은 `SHARED` arena 모드여야 합니다.
///
/// @author Q. T. Felix
public final class SharedStore implements AutoCloseable {

    private final Map<String, SensitiveDataContainer> store = new HashMap<>();
    private boolean closed = false;

    /// 키에 값을 저장합니다(덮어쓰기). 이전 값이 있으면 소거합니다.
    public synchronized void put(final @NotNull String key, final byte @NotNull [] value) throws IssException {
        ensureOpen();
        final SensitiveDataContainer previous = store.put(key, allocate(value));
        if (previous != null)
            previous.close();
    }

    /// 키의 값을 `heap` 바이트로 반환합니다. 없으면 `null`.
    public synchronized byte @Nullable [] get(final @NotNull String key) throws IssException {
        ensureOpen();
        final SensitiveDataContainer sdc = store.get(key);
        if (sdc == null)
            return null;
        try {
            return SdcBytes.export(sdc);
        } catch (ELIBSecurityProcessException e) {
            throw new IssException("저장 값 추출에 실패했습니다", e);
        }
    }

    /// 키를 삭제하고 값을 소거합니다. 존재 여부를 반환합니다.
    public synchronized boolean delete(final @NotNull String key) {
        ensureOpen();
        final SensitiveDataContainer sdc = store.remove(key);
        if (sdc == null)
            return false;
        sdc.close();
        return true;
    }

    public synchronized boolean exists(final @NotNull String key) {
        ensureOpen();
        return store.containsKey(key);
    }

    public synchronized @NotNull Set<String> keys() {
        ensureOpen();
        return new TreeSet<>(store.keySet());
    }

    public synchronized int size() {
        return store.size();
    }

    private SensitiveDataContainer allocate(final byte[] value) throws IssException {
        try {
            return new SensitiveDataContainer(value.clone(), true);
        } catch (ELIBSecurityProcessException e) {
            throw new IssException("저장 값 컨테이너 생성에 실패했습니다", e);
        }
    }

    private void ensureOpen() {
        if (closed)
            throw new IllegalStateException("이미 종료된 공유 저장소입니다");
    }

    /// 저장소를 종료하고 모든 값을 소거합니다.
    @Override
    public synchronized void close() {
        if (closed)
            return;
        closed = true;
        for (final SensitiveDataContainer sdc : store.values()) {
            try {
                sdc.close();
            } catch (Exception ignored) {
                // 개별 소거 실패는 나머지 소거를 막지 않음
            }
        }
        store.clear();
    }
}
