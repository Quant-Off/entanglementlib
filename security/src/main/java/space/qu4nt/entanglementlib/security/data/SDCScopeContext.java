package space.qu4nt.entanglementlib.security.data;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/// 보안 작업 흐름 내에서 생성되는 모든 민감 데이터 컨테이너를 추적하고,
/// 스코프 종료 시 일괄 소거(zeroize)를 보장하는 컨텍스트 클래스입니다.
///
/// @author Q. T. Felix
/// @since 1.1.1
@Slf4j
public final class SDCScopeContext implements AutoCloseable {

    private final List<@NotNull SensitiveDataContainer> trackedContainers = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean isAlive = true;

    /// 스코프 내에서 새로운 [SensitiveDataContainer]를 할당하는 메소드입니다.
    /// 생성된 컨테이너는 자동으로 현재 스코프에 바인딩됩니다.
    public SensitiveDataContainer allocate(int size) {
        checkAlive();
        SensitiveDataContainer container = new SensitiveDataContainer(size);
        trackedContainers.add(container);
        return container;
    }

    /// 기존 바이트 배열로부터 데이터 소유권을 이전받는 컨테이너를 생성하는 메소드입니다.
    public SensitiveDataContainer allocate(byte[] from, boolean forceWipe) {
        checkAlive();
        SensitiveDataContainer container = new SensitiveDataContainer(from, forceWipe);
        trackedContainers.add(container);
        return container;
    }

    private void checkAlive() {
        if (!isAlive)
            throw new IllegalStateException("이미 소거 완료된 보안 스코프입니다!");
    }

    @Override
    public void close() {
        if (!isAlive) return;
        isAlive = false;

        // 스냅샷 소거
        synchronized (trackedContainers) {
            for (int i = trackedContainers.size() - 1; i >= 0; i--) {
                SensitiveDataContainer sdc = trackedContainers.get(i);
                try {
                    sdc.close();
                } catch (Exception e) {
                    log.error("컨텍스트 내부 컨테이너 소거 중 오류 발생", e);
                }
            }
            trackedContainers.clear();
        }
    }
}
