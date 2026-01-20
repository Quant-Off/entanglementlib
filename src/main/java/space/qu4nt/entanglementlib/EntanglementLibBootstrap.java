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

package space.qu4nt.entanglementlib;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

import java.security.SecureRandom;

/**
 * 얽힘 라이브러리의 몇 가지 기능을 외부에서 즉시 호출할 수도 있지만
 * 이 경우 정적 블록에 대한 메모리 할당 및 그에 상응하는 작업의 시간 복잡도가
 * 증가합니다. 이를 해결하기 위해 만들어진 내부 로딩 부트스트랩 클래스입니다.
 * <p>
 * 이 클래스가 내부에서 사용되는 경우는 전달받은 외부 프로젝트(호출자)의 이름을
 * 사용하는 때 이외엔 없으며, 호출되어서도 안 됩니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
@Getter
@Setter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public final class EntanglementLibBootstrap {

    static {
        log.debug("얽힘 라이브러리(EntanglementLib) 등록");
    }

    @ApiStatus.Internal
    private @NotNull String projectName;

    @ExternalPattern
    public static EntanglementLibBootstrap registerEntanglementLib(@NotNull String projectName, boolean setBCProviders) {
        if (setBCProviders)
            InternalFactory.registerInternalEntanglementLib();
        return new EntanglementLibBootstrap(projectName);
    }

    @ExternalPattern
    public @NotNull SecureRandom getSafeRandom() {
        return InternalFactory.getSafeRandom();
    }
}
