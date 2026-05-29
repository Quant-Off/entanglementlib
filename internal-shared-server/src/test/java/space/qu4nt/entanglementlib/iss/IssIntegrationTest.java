package space.qu4nt.entanglementlib.iss;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import space.qu4nt.entanglementlib.iss.exception.IssException;
import space.qu4nt.entanglementlib.iss.handler.IssResponse;
import space.qu4nt.entanglementlib.iss.security.IssPsk;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IssIntegrationTest {

    private static final String PSK_HEX = "0123456789abcdef".repeat(4); // 32 bytes
    private static final String OTHER_PSK_HEX = "fedcba9876543210".repeat(4);

    @BeforeAll
    static void init() {
        Iss.initializeVerified();
    }

    @Test
    @Timeout(30)
    @DisplayName("핸드셰이크 후 PING/PUT/GET/EXISTS/LIST/DEL/STATUS 전 과정이 동작한다")
    void fullRoundTrip() throws Exception {
        try (SensitiveDataContainer serverPsk = IssPsk.fromHex(PSK_HEX);
             IssServer server = IssServer.builder().port(0).psk(serverPsk).build()) {
            server.start();

            try (SensitiveDataContainer clientPsk = IssPsk.fromHex(PSK_HEX);
                 IssClient client = connectTo(server.port(), clientPsk)) {

                client.ping();

                client.put("config", "hello".getBytes(StandardCharsets.UTF_8));
                assertThat(client.get("config")).asString().isEqualTo("hello");
                assertThat(client.exists("config")).isTrue();
                assertThat(client.list()).contains("config");

                assertThat(client.delete("config")).isTrue();
                assertThat(client.get("config")).isNull();
                assertThat(client.exists("config")).isFalse();

                assertThat(client.status()).contains("ISS SERVER");
            }
        }
    }

    @Test
    @Timeout(30)
    @DisplayName("커스텀 핸들러를 등록하여 호출할 수 있다")
    void customHandler() throws Exception {
        try (SensitiveDataContainer serverPsk = IssPsk.fromHex(PSK_HEX);
             IssServer server = IssServer.builder().port(0).psk(serverPsk).build()) {
            server.register("ECHO", context -> IssResponse.of(context.payload()));
            server.start();

            try (SensitiveDataContainer clientPsk = IssPsk.fromHex(PSK_HEX);
                 IssClient client = connectTo(server.port(), clientPsk)) {

                final IssResponse response = client.request("ECHO", "ping-back".getBytes(StandardCharsets.UTF_8));
                assertThat(response.status().isOk()).isTrue();
                assertThat(response.bodyAsText()).isEqualTo("ping-back");
            }
        }
    }

    @Test
    @Timeout(30)
    @DisplayName("바이너리 값도 무손실로 왕복한다")
    void binaryValueRoundTrip() throws Exception {
        try (SensitiveDataContainer serverPsk = IssPsk.fromHex(PSK_HEX);
             IssServer server = IssServer.builder().port(0).psk(serverPsk).build()) {
            server.start();

            final byte[] value = new byte[512];
            for (int i = 0; i < value.length; i++)
                value[i] = (byte) (i * 31 + 7);

            try (SensitiveDataContainer clientPsk = IssPsk.fromHex(PSK_HEX);
                 IssClient client = connectTo(server.port(), clientPsk)) {
                client.put("blob", value);
                assertThat(client.get("blob")).isEqualTo(value);
            }
        }
    }

    @Test
    @Timeout(30)
    @DisplayName("PSK 가 다르면 키 확인 단계에서 인증이 실패한다 (fail-closed)")
    void mismatchedPskFails() throws Exception {
        try (SensitiveDataContainer serverPsk = IssPsk.fromHex(PSK_HEX);
             IssServer server = IssServer.builder().port(0).psk(serverPsk).build()) {
            server.start();

            try (SensitiveDataContainer wrongPsk = IssPsk.fromHex(OTHER_PSK_HEX)) {
                final int port = server.port();
                assertThatThrownBy(() -> connectTo(port, wrongPsk)).isInstanceOf(IssException.class);
            }
        }
    }

    private static IssClient connectTo(final int port, final SensitiveDataContainer psk) throws IssException {
        return IssClient.connect(IssClientConfig.builder()
                .host("127.0.0.1")
                .port(port)
                .psk(psk)
                .build());
    }
}
