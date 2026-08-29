package space.qu4nt.entanglementlib.iss.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import space.qu4nt.entanglementlib.iss.ISS;
import space.qu4nt.entanglementlib.iss.ISSClientConfig;
import space.qu4nt.entanglementlib.iss.ISSServer;
import space.qu4nt.entanglementlib.iss.security.ISSPSK;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

// LHW 브리지 전 과정 통합 검증. 실제 ISS 서버를 띄우고 브리지를 경유해
// 인증, 오리진 차단, KV 왕복, 정적 서빙, 경로 이탈 차단을 확인한다
class LhwServerTest {

    private static final String PSK_HEX = "0123456789abcdef".repeat(4);

    private static ISSServer iss;
    private static SensitiveDataContainer serverPsk;
    private static SensitiveDataContainer clientPsk;
    private static LhwServer lhw;
    private static LhwToken.Issued issued;
    private static Path webDir;
    private static HttpClient http;

    @BeforeAll
    static void boot() throws Exception {
        ISS.initializeVerified();
        serverPsk = ISSPSK.fromHex(PSK_HEX);
        iss = ISSServer.builder().port(0).psk(serverPsk).build();
        iss.start();

        webDir = Files.createTempDirectory("lhw-web");
        Files.writeString(webDir.resolve("index.html"), "<!doctype html><title>lhw</title>");
        Files.createDirectory(webDir.resolve("assets"));
        Files.writeString(webDir.resolve("assets/app-abc123.js"), "console.log(1)");

        clientPsk = ISSPSK.fromHex(PSK_HEX);
        issued = LhwToken.issue();
        lhw = LhwServer.builder()
                .target(ISSClientConfig.builder().host("127.0.0.1").port(iss.port()).psk(clientPsk).build())
                .token(issued.verifier())
                .webDir(webDir)
                .httpPort(0)
                .build();
        lhw.start();
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void shutdown() {
        if (lhw != null) lhw.close();
        if (iss != null) iss.close();
        if (serverPsk != null) serverPsk.close();
        if (clientPsk != null) clientPsk.close();
    }

    private static HttpRequest.Builder request(final String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + lhw.port() + path))
                .header("Authorization", "Bearer " + issued.tokenHex());
    }

    private static HttpResponse<String> send(final HttpRequest req) throws IOException, InterruptedException {
        return http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    @Test
    @Timeout(30)
    @DisplayName("토큰 없는 API 요청은 401 로 거부된다")
    void rejectsMissingToken() throws Exception {
        final HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + lhw.port() + "/api/status")).GET().build());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).contains("토큰");
    }

    @Test
    @Timeout(30)
    @DisplayName("잘못된 토큰은 401 로 거부된다")
    void rejectsWrongToken() throws Exception {
        final HttpResponse<String> response = send(HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + lhw.port() + "/api/status"))
                .header("Authorization", "Bearer " + "0".repeat(64)).GET().build());
        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    @Timeout(30)
    @DisplayName("비루프백 오리진은 403 으로 거부된다")
    void rejectsForeignOrigin() throws Exception {
        final HttpResponse<String> response = send(
                request("/api/status").header("Origin", "http://evil.example").GET().build());
        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    @Timeout(30)
    @DisplayName("루프백 오리진은 허용된다")
    void allowsLoopbackOrigin() throws Exception {
        final HttpResponse<String> response = send(
                request("/api/status").header("Origin", "http://127.0.0.1:5173").GET().build());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("ISS SERVER");
    }

    @Test
    @Timeout(30)
    @DisplayName("PUT -> 목록 -> 열람 -> 삭제 전 과정이 브리지를 경유해 동작한다")
    void kvRoundTrip() throws Exception {
        final byte[] value = "비밀 값 v1".getBytes(StandardCharsets.UTF_8);
        final HttpResponse<String> put = send(request("/api/keys/roundtrip")
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofByteArray(value)).build());
        assertThat(put.statusCode()).isEqualTo(200);

        final HttpResponse<String> list = send(request("/api/keys").GET().build());
        assertThat(list.statusCode()).isEqualTo(200);
        assertThat(list.body()).contains("\"roundtrip\"");

        final HttpResponse<String> reveal = send(request("/api/keys/roundtrip/value").GET().build());
        assertThat(reveal.statusCode()).isEqualTo(200);
        assertThat(reveal.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(reveal.body()).contains(Base64.getEncoder().encodeToString(value));

        final HttpResponse<String> delete = send(request("/api/keys/roundtrip").DELETE().build());
        assertThat(delete.statusCode()).isEqualTo(200);

        final HttpResponse<String> gone = send(request("/api/keys/roundtrip/value").GET().build());
        assertThat(gone.statusCode()).isEqualTo(404);
    }

    @Test
    @Timeout(30)
    @DisplayName("URL 인코딩된 한글 키가 무손실로 왕복한다")
    void koreanKeyRoundTrip() throws Exception {
        final String encoded = java.net.URLEncoder.encode("한글 키", StandardCharsets.UTF_8);
        final HttpResponse<String> put = send(request("/api/keys/" + encoded)
                .PUT(HttpRequest.BodyPublishers.ofString("v")).build());
        assertThat(put.statusCode()).isEqualTo(200);

        final HttpResponse<String> list = send(request("/api/keys").GET().build());
        assertThat(list.body()).contains("한글 키");

        assertThat(send(request("/api/keys/" + encoded).DELETE().build()).statusCode()).isEqualTo(200);
    }

    @Test
    @Timeout(30)
    @DisplayName("빈 PUT 본문은 400 으로 거부된다")
    void rejectsEmptyValue() throws Exception {
        final HttpResponse<String> response = send(request("/api/keys/empty")
                .PUT(HttpRequest.BodyPublishers.noBody()).build());
        assertThat(response.statusCode()).isEqualTo(400);
    }

    @Test
    @Timeout(30)
    @DisplayName("PING 은 RTT 마이크로초를 반환한다")
    void pingReturnsRtt() throws Exception {
        final HttpResponse<String> response = send(request("/api/ping").GET().build());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"ok\":true").contains("rttMicros");
    }

    @Test
    @Timeout(30)
    @DisplayName("정적 웹은 보안 헤더와 함께 서빙되고 SPA 폴백이 동작한다")
    void staticServingWithSecurityHeaders() throws Exception {
        final HttpResponse<String> index = send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + lhw.port() + "/")).GET().build());
        assertThat(index.statusCode()).isEqualTo(200);
        assertThat(index.body()).contains("lhw");
        assertThat(index.headers().firstValue("Content-Security-Policy")).isPresent();
        assertThat(index.headers().firstValue("X-Content-Type-Options")).hasValue("nosniff");
        assertThat(index.headers().firstValue("Cache-Control")).hasValue("no-store");

        final HttpResponse<String> asset = send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + lhw.port() + "/assets/app-abc123.js")).GET().build());
        assertThat(asset.statusCode()).isEqualTo(200);
        assertThat(asset.headers().firstValue("Cache-Control").orElse("")).contains("immutable");

        // 확장자 없는 경로는 SPA 폴백으로 index.html
        final HttpResponse<String> fallback = send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + lhw.port() + "/keys")).GET().build());
        assertThat(fallback.statusCode()).isEqualTo(200);
        assertThat(fallback.body()).contains("lhw");
    }

    @Test
    @Timeout(30)
    @DisplayName("경로 이탈(../) 접근은 차단된다")
    void blocksPathTraversal() throws Exception {
        final Path secret = webDir.getParent().resolve("lhw-secret.txt");
        Files.writeString(secret, "topsecret");
        try {
            final HttpResponse<String> response = send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + lhw.port() + "/assets/%2e%2e/%2e%2e/lhw-secret.txt"))
                    .GET().build());
            assertThat(response.statusCode()).isEqualTo(404);
            assertThat(response.body()).doesNotContain("topsecret");
        } finally {
            Files.deleteIfExists(secret);
        }
    }

    @Test
    @Timeout(30)
    @DisplayName("타겟 ISS 서버가 죽으면 502 로 보고한다")
    void reportsBridgeFailure() throws Exception {
        try (SensitiveDataContainer psk = ISSPSK.fromHex(PSK_HEX);
             LhwServer orphan = LhwServer.builder()
                     .target(ISSClientConfig.builder().host("127.0.0.1").port(1).psk(psk).build())
                     .token(issued.verifier())
                     .httpPort(0)
                     .build()) {
            orphan.start();
            final HttpResponse<String> response = send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + orphan.port() + "/api/status"))
                    .header("Authorization", "Bearer " + issued.tokenHex()).GET().build());
            assertThat(response.statusCode()).isEqualTo(502);
        }
    }

    @Test
    @Timeout(30)
    @DisplayName("토큰 검증기는 형식이 다른 입력을 즉시 거부한다")
    void tokenVerifierRejectsMalformed() {
        assertThat(issued.verifier().verify(null)).isFalse();
        assertThat(issued.verifier().verify("")).isFalse();
        assertThat(issued.verifier().verify("short")).isFalse();
        assertThat(issued.verifier().verify(issued.tokenHex())).isTrue();
    }

    @Test
    @Timeout(30)
    @DisplayName("JSON 직렬화기는 특수 문자를 정확히 이스케이프한다")
    void jsonEscaping() {
        assertThat(LhwJson.object("k", "a\"b\\c\nd"))
                .isEqualTo("{\"k\":\"a\\\"b\\\\c\\nd\"}");
        assertThat(LhwJson.stringArray(java.util.List.of("가", "b")))
                .isEqualTo("[\"가\",\"b\"]");
        assertThat(LhwJson.object("n", 3, "b", true))
                .isEqualTo("{\"n\":3,\"b\":true}");
    }
}
