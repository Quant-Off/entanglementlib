/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/// 명령 이름 -> [IssRequestHandler] 레지스트리입니다. 다수의 연결 스레드가 동시에 조회하므로
/// 스레드 안전합니다.
///
/// @author Q. T. Felix
public final class HandlerRegistry {

    private final ConcurrentMap<String, IssRequestHandler> handlers = new ConcurrentHashMap<>();

    public void register(final @NotNull String command, final @NotNull IssRequestHandler handler) {
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(handler, "handler");
        handlers.put(command, handler);
    }

    public @Nullable IssRequestHandler resolve(final @NotNull String command) {
        return handlers.get(command);
    }

    public boolean contains(final @NotNull String command) {
        return handlers.containsKey(command);
    }

    public @NotNull Set<String> commands() {
        return Collections.unmodifiableSet(new TreeSet<>(handlers.keySet()));
    }
}
