/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.security.EntLibKeyDestroyException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.collection.SafeList;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;

/**
 * 민감 데이터의 생명 주기(life-cycle)를 관리하기 위한 클래스입니다.
 * 레지스트리에 민감 데이터가 등록되는 경우 사용 종료 시 즉시 파기됩니다.
 * <p>
 * 확실한 소거를 위해서는 {@link #destroyActions} 전역 변수에는
 * 민감 정보의 원본 값만이 포함되어야 합니다. 복사본 전달 시 예기치 못한
 * 위치(메모리 내)에서 데이터가 잔류할 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
class SensitiveRegistry {

    // 파기 동작을 수행할 Runnable 리스트
    private final SafeList<Runnable> destroyActions = new SafeList<>();

    /**
     * 파기 가능한 객체를 등록하는 메소드입니다.
     *
     * @param resource 파기 가능한 객체
     * @return 등록된 객체
     */
    <T> T register(T resource, @Nullable EntLibKey.CustomWiper<?> wiperCallback) {
        if (resource != null) {
            if (resource instanceof Key)
                throw new EntLibKeyDestroyException(KeyService.class, "key-instance-not-allowed-exc");
            destroyActions.add(() -> {
                if (resource instanceof byte[] b) {
                    KeyDestroyHelper.zeroing(b);
                } else if (resource instanceof char[] c) {
                    KeyDestroyHelper.zeroing(c);
                } else { // EntLibKey
                    if (resource instanceof EntLibKeyPair wrap) {
                        // noinspection unchecked
                        wrap.wipe((EntLibKey.CustomWiper<KeyPair>) wiperCallback);
                    } else if (resource instanceof EntLibSecretKey wrap) {
                        // noinspection unchecked
                        wrap.wipe((EntLibKey.CustomWiper<SecretKey>) wiperCallback);
                    }
                }
            });
        }
        return resource;
    }

    <T> T register(T resource) {
        return register(resource, null);
    }

    /**
     * 등록된 모든 자원을 파기하는 메소드입니다.
     */
    public void destroyAll() {
        log.info(destroyActions.size() + "");
        // 최근에 등록한 자원부터 역순으로 파기하는 것이 안전할 수 있음
        for (int i = destroyActions.size() - 1; i >= 0; i--) {
            try {
                destroyActions.get(i).run();
            } catch (Exception e) {
                log.error(LanguageInstanceBased.create(SensitiveRegistry.class)
                        .argsNonTopKey("debug-destroy-during-exc"), e);
            }
        }
        destroyActions.clear();
    }

}
