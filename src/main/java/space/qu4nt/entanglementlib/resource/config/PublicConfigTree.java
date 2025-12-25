/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

/**
 * {@code public} 디렉토리에 정의된 구성 파일 {@code configuration.json}을
 * 역/직렬화 하기 위해 사용되는 클래스입니다.
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
