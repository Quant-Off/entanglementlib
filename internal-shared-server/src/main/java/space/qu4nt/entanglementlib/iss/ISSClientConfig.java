/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.iss.protocol.WireConstants;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.util.Objects;

/// [ISSClient] 구성입니다. [#builder()]로 생성합니다.
///
/// @author Q. T. Felix
public final class ISSClientConfig {

    private final String host;
    private final int port;
    private final SensitiveDataContainer psk;
    private final int connectTimeoutMillis;
    private final int handshakeTimeoutMillis;
    private final int idleTimeoutMillis;

    private ISSClientConfig(final Builder builder) {
        this.host = builder.host;
        this.port = builder.port;
        this.psk = Objects.requireNonNull(builder.psk, "psk");
        this.connectTimeoutMillis = builder.connectTimeoutMillis;
        this.handshakeTimeoutMillis = builder.handshakeTimeoutMillis;
        this.idleTimeoutMillis = builder.idleTimeoutMillis;
    }

    public static @NotNull Builder builder() {
        return new Builder();
    }

    public @NotNull String host() {
        return host;
    }

    public int port() {
        return port;
    }

    public @NotNull SensitiveDataContainer psk() {
        return psk;
    }

    public int connectTimeoutMillis() {
        return connectTimeoutMillis;
    }

    public int handshakeTimeoutMillis() {
        return handshakeTimeoutMillis;
    }

    public int idleTimeoutMillis() {
        return idleTimeoutMillis;
    }

    /// [ISSClientConfig] 빌더입니다.
    public static final class Builder {

        private String host = "127.0.0.1";
        private int port = -1;
        private SensitiveDataContainer psk;
        private int connectTimeoutMillis = 5_000;
        private int handshakeTimeoutMillis = WireConstants.HANDSHAKE_TIMEOUT_MILLIS;
        private int idleTimeoutMillis = WireConstants.IDLE_READ_TIMEOUT_MILLIS;

        private Builder() {
        }

        public @NotNull Builder host(final @NotNull String host) {
            this.host = Objects.requireNonNull(host, "host");
            return this;
        }

        public @NotNull Builder port(final int port) {
            this.port = port;
            return this;
        }

        public @NotNull Builder psk(final @NotNull SensitiveDataContainer psk) {
            this.psk = psk;
            return this;
        }

        public @NotNull Builder connectTimeoutMillis(final int millis) {
            this.connectTimeoutMillis = millis;
            return this;
        }

        public @NotNull Builder handshakeTimeoutMillis(final int millis) {
            this.handshakeTimeoutMillis = millis;
            return this;
        }

        public @NotNull Builder idleTimeoutMillis(final int millis) {
            this.idleTimeoutMillis = millis;
            return this;
        }

        public @NotNull ISSClientConfig build() {
            if (port < 1 || port > 65535)
                throw new IllegalArgumentException("포트가 유효하지 않습니다: " + port);
            return new ISSClientConfig(this);
        }
    }
}
