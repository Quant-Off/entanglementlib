/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

/**
 * 뭐하는 클래스임?
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class PublicConfigTree {

    private String language;
    private Secure secure;

    @Getter
    @Setter
    @ToString
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Secure {
        private boolean enabledExperimental;
        private TLS tls;

        @Getter
        @Setter
        @ToString
        @NoArgsConstructor
        @AllArgsConstructor
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static final class TLS {
            private String protocol;
            private Cert cert;
            private int maxHandshakeMessageSize;

            @Getter
            @Setter
            @ToString
            @NoArgsConstructor
            @AllArgsConstructor
            @JsonInclude(JsonInclude.Include.NON_NULL)
            public static final class Cert {
                private boolean enabledPQC;
                private String root;
                private String server;
            }
        }
    }

}
