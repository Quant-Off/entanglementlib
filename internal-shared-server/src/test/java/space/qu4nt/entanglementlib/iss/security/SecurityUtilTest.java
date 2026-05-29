package space.qu4nt.entanglementlib.iss.security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.iss.ISS;
import space.qu4nt.entanglementlib.iss.exception.ISSException;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.net.InetAddress;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityUtilTest {

    @BeforeAll
    static void init() {
        ISS.initializeVerified();
    }

    @Test
    @DisplayName("유효한 32바이트 hex PSK 를 적재한다")
    void loadsValidPsk() throws Exception {
        final String hex = "a".repeat(64); // 32 bytes
        try (SensitiveDataContainer psk = ISSPSK.fromHex(hex)) {
            assertThat(psk).isNotNull();
        }
    }

    @Test
    @DisplayName("32바이트 미만 PSK 는 거부한다")
    void rejectsShortPsk() {
        assertThatThrownBy(() -> ISSPSK.fromHex("abcd")).isInstanceOf(ISSException.class);
    }

    @Test
    @DisplayName("전부 0인 PSK 는 거부한다")
    void rejectsAllZeroPsk() {
        assertThatThrownBy(() -> ISSPSK.fromHex("0".repeat(64))).isInstanceOf(ISSException.class);
    }

    @Test
    @DisplayName("루프백 바인드는 옵트인 없이 허용된다")
    void loopbackBindAllowed() throws Exception {
        final InetAddress loopback = BindPolicy.resolve("127.0.0.1");
        assertThat(loopback.isLoopbackAddress()).isTrue();
        assertThatCode(() -> BindPolicy.validateBind(loopback, false)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("비루프백 바인드는 옵트인 없이는 차단된다")
    void nonLoopbackBlockedWithoutOptIn() throws Exception {
        final InetAddress lan = InetAddress.getByName("10.0.0.1");
        assertThatThrownBy(() -> BindPolicy.validateBind(lan, false)).isInstanceOf(ISSException.class);
        assertThatCode(() -> BindPolicy.validateBind(lan, true)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("허용목록이 비면 임의 피어 허용, 있으면 목록만 허용")
    void peerAllowlist() throws Exception {
        final InetAddress a = InetAddress.getByName("10.0.0.1");
        final InetAddress b = InetAddress.getByName("10.0.0.2");

        assertThat(BindPolicy.isPeerAllowed(a, List.of())).isTrue();
        assertThat(BindPolicy.isPeerAllowed(a, List.of(a))).isTrue();
        assertThat(BindPolicy.isPeerAllowed(b, List.of(a))).isFalse();
    }
}
