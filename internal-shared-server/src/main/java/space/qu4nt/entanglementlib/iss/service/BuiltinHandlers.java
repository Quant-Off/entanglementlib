/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.service;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.iss.handler.HandlerRegistry;
import space.qu4nt.entanglementlib.iss.handler.IssResponse;
import space.qu4nt.entanglementlib.iss.handler.KvCodec;

import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

/// 폐쇄망 공유 인프라의 기본 명령 집합을 [HandlerRegistry]에 등록합니다.
///
/// 제공 명령: PING, STATUS, PUT, GET, DEL, EXISTS, LIST. 모두 내장 [SharedStore]에 연결됩니다.
/// 사용자는 이 위에 커스텀 명령을 추가 등록할 수 있습니다.
///
/// @author Q. T. Felix
public final class BuiltinHandlers {

    public static final String PING = "PING";
    public static final String STATUS = "STATUS";
    public static final String PUT = "PUT";
    public static final String GET = "GET";
    public static final String DEL = "DEL";
    public static final String EXISTS = "EXISTS";
    public static final String LIST = "LIST";

    private BuiltinHandlers() {
        throw new AssertionError("cannot access");
    }

    /// 기본 명령을 모두 등록합니다.
    ///
    /// @param registry   등록 대상 레지스트리
    /// @param store      값을 보관할 공유 저장소
    /// @param statusText STATUS 명령이 반환할 서버 상태 텍스트 공급자
    public static void registerAll(final @NotNull HandlerRegistry registry,
                                   final @NotNull SharedStore store,
                                   final @NotNull Supplier<String> statusText) {

        registry.register(PING, context -> IssResponse.ok("pong".getBytes(StandardCharsets.UTF_8)));

        registry.register(STATUS, context -> IssResponse.ok(statusText.get().getBytes(StandardCharsets.UTF_8)));

        registry.register(PUT, context -> {
            final KvCodec.KeyValue kv = KvCodec.decodeKeyValue(context.payload());
            store.put(kv.key(), kv.value());
            return IssResponse.ok();
        });

        registry.register(GET, context -> {
            final String key = KvCodec.decodeKey(context.payload());
            final byte[] value = store.get(key);
            return value == null ? IssResponse.notFound() : IssResponse.ok(value);
        });

        registry.register(DEL, context -> {
            final String key = KvCodec.decodeKey(context.payload());
            return store.delete(key) ? IssResponse.ok() : IssResponse.notFound();
        });

        registry.register(EXISTS, context -> {
            final String key = KvCodec.decodeKey(context.payload());
            return IssResponse.ok(new byte[]{(byte) (store.exists(key) ? 1 : 0)});
        });

        registry.register(LIST, context -> {
            final String joined = String.join("\n", store.keys());
            return IssResponse.ok(joined.getBytes(StandardCharsets.UTF_8));
        });
    }
}
