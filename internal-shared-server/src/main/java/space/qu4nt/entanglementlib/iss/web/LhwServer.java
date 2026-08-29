/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.iss.ISSClient;
import space.qu4nt.entanglementlib.iss.ISSClientConfig;
import space.qu4nt.entanglementlib.iss.exception.ISSException;
import space.qu4nt.entanglementlib.iss.protocol.WireConstants;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/// ISS 웹 콘솔을 위한 Local Hosted Web(LHW) 브리지 서버입니다.
///
/// 브라우저는 ISS의 TCP 바이너리 프로토콜을 직접 말할 수 없으므로, 이 브리지가 루프백 전용
/// HTTP(JSON)를 받아 검증된 [ISSClient] 경로(PSK 상호 인증 + ChaCha20 채널)로 중계합니다.
/// PSK와 암호 구현은 JVM 밖으로 나가지 않습니다.
///
/// # Security Note
/// - 바인드는 항상 루프백입니다. 옵션으로도 해제할 수 없습니다.
/// - 모든 `/api` 요청은 기동 시 1회 발급된 Bearer 토큰([LhwToken])을 요구합니다.
/// - `Origin` 헤더가 있으면 루프백 오리진만 허용합니다(교차 출처 탭 차단).
/// - 값 응답은 `Cache-Control: no-store`로 내려 브라우저 캐시 잔존을 막습니다.
/// - ISS 연결은 요청마다 새로 열고 닫습니다. 세션 상태를 남기지 않고, 매 요청이 PSK 상호
///   인증을 다시 통과합니다.
///
/// @author Q. T. Felix
public final class LhwServer implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(LhwServer.class);

    private static final String API_PREFIX = "/api/";
    private static final int MAX_KEY_CHARS = 512;
    /// 단일 프레임 한계(1 MiB)에서 명령·헤더 여유를 뺀 PUT 본문 상한
    private static final int MAX_VALUE_BYTES = WireConstants.MAX_FRAME - 1024;
    private static final Set<String> LOOPBACK_ORIGIN_HOSTS = Set.of("127.0.0.1", "localhost", "[::1]", "::1");

    private final ISSClientConfig target;
    private final LhwToken token;
    private final @Nullable Path webRoot;
    private final HttpServer http;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    private LhwServer(final Builder builder) throws ISSException {
        this.target = Objects.requireNonNull(builder.target, "target");
        this.token = Objects.requireNonNull(builder.token, "token");
        this.webRoot = builder.webDir == null ? null : builder.webDir.toAbsolutePath().normalize();
        if (webRoot != null && !Files.isDirectory(webRoot))
            throw new ISSException("정적 웹 디렉터리가 존재하지 않습니다: " + webRoot);
        try {
            this.http = HttpServer.create(
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), builder.httpPort), 0);
        } catch (IOException e) {
            throw new ISSException("LHW HTTP 서버 바인드에 실패했습니다 (포트 " + builder.httpPort + ")", e);
        }
        http.setExecutor(executor);
        http.createContext("/", this::dispatch);
    }

    public static @NotNull Builder builder() {
        return new Builder();
    }

    public void start() {
        http.start();
        log.info("LHW 브리지 시작: http://127.0.0.1:{} -> ISS {}:{}", port(), target.host(), target.port());
    }

    public int port() {
        return http.getAddress().getPort();
    }

    @Override
    public void close() {
        http.stop(0);
        executor.shutdown();
        try {
            if (!executor.awaitTermination(3, TimeUnit.SECONDS))
                executor.shutdownNow();
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ── 디스패치 ─────────────────────────────────────────────

    private void dispatch(final HttpExchange exchange) {
        try (exchange) {
            baseHeaders(exchange);
            if (!originAllowed(exchange)) {
                sendJson(exchange, 403, LhwJson.object("error", "허용되지 않은 오리진입니다"));
                return;
            }
            final String path = exchange.getRequestURI().getPath();
            if (path.startsWith(API_PREFIX)) {
                handleApi(exchange, path.substring(API_PREFIX.length()));
            } else {
                handleStatic(exchange, path);
            }
        } catch (Exception e) {
            log.warn("LHW 요청 처리 실패", e);
            try {
                sendJson(exchange, 500, LhwJson.object("error", "내부 오류가 발생했습니다"));
            } catch (IOException ignored) {
                // 응답 불가 시 연결 종료로 갈음
            }
        }
    }

    // ── API ─────────────────────────────────────────────────

    private void handleApi(final HttpExchange exchange, final String route) throws IOException {
        if (!authorized(exchange)) {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
            sendJson(exchange, 401, LhwJson.object("error", "접속 토큰이 없거나 올바르지 않습니다"));
            return;
        }
        exchange.getResponseHeaders().set("Cache-Control", "no-store");

        final String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        final List<String> segments = splitRoute(route);
        try {
            if (segments.size() == 1 && segments.getFirst().equals("status") && method.equals("GET")) {
                apiStatus(exchange);
            } else if (segments.size() == 1 && segments.getFirst().equals("ping") && method.equals("GET")) {
                apiPing(exchange);
            } else if (segments.size() == 1 && segments.getFirst().equals("keys") && method.equals("GET")) {
                apiKeys(exchange);
            } else if (segments.size() == 3 && segments.getFirst().equals("keys")
                    && segments.get(2).equals("value") && method.equals("GET")) {
                apiRevealValue(exchange, requireKey(segments.get(1)));
            } else if (segments.size() == 2 && segments.getFirst().equals("keys")) {
                switch (method) {
                    case "PUT" -> apiPutValue(exchange, requireKey(segments.get(1)));
                    case "DELETE" -> apiDeleteKey(exchange, requireKey(segments.get(1)));
                    default -> sendJson(exchange, 405, LhwJson.object("error", "허용되지 않은 메소드입니다"));
                }
            } else {
                sendJson(exchange, 404, LhwJson.object("error", "알 수 없는 API 경로입니다"));
            }
        } catch (BadRequest e) {
            sendJson(exchange, 400, LhwJson.object("error", e.getMessage()));
        } catch (ISSException e) {
            log.warn("ISS 중계 실패: {}", e.getMessage());
            sendJson(exchange, 502, LhwJson.object("error", "ISS 서버 중계에 실패했습니다: " + e.getMessage()));
        }
    }

    private void apiStatus(final HttpExchange exchange) throws ISSException, IOException {
        final String status;
        try (ISSClient client = ISSClient.connect(target)) {
            status = client.status();
        }
        sendJson(exchange, 200, LhwJson.object("status", status));
    }

    private void apiPing(final HttpExchange exchange) throws ISSException, IOException {
        final long started = System.nanoTime();
        try (ISSClient client = ISSClient.connect(target)) {
            client.ping();
        }
        final long rttMicros = (System.nanoTime() - started) / 1_000;
        sendJson(exchange, 200, LhwJson.object("ok", true, "rttMicros", rttMicros));
    }

    private void apiKeys(final HttpExchange exchange) throws ISSException, IOException {
        final List<String> keys;
        try (ISSClient client = ISSClient.connect(target)) {
            keys = client.list();
        }
        sendJson(exchange, 200, LhwJson.object("keys", new LhwJson.Raw(LhwJson.stringArray(keys))));
    }

    private void apiRevealValue(final HttpExchange exchange, final String key) throws ISSException, IOException {
        final byte[] value;
        try (ISSClient client = ISSClient.connect(target)) {
            value = client.get(key);
        }
        if (value == null) {
            sendJson(exchange, 404, LhwJson.object("error", "키를 찾을 수 없습니다"));
            return;
        }
        sendJson(exchange, 200, LhwJson.object(
                "key", key,
                "bytes", value.length,
                "valueBase64", Base64.getEncoder().encodeToString(value)));
    }

    private void apiPutValue(final HttpExchange exchange, final String key)
            throws ISSException, IOException, BadRequest {
        final byte[] value = exchange.getRequestBody().readNBytes(MAX_VALUE_BYTES + 1);
        if (value.length > MAX_VALUE_BYTES) {
            sendJson(exchange, 413, LhwJson.object("error", "값이 너무 큽니다 (최대 " + MAX_VALUE_BYTES + " 바이트)"));
            return;
        }
        if (value.length == 0)
            throw new BadRequest("값이 비어 있습니다");
        try (ISSClient client = ISSClient.connect(target)) {
            client.put(key, value);
        }
        sendJson(exchange, 200, LhwJson.object("ok", true));
    }

    private void apiDeleteKey(final HttpExchange exchange, final String key) throws ISSException, IOException {
        final boolean existed;
        try (ISSClient client = ISSClient.connect(target)) {
            existed = client.delete(key);
        }
        if (existed)
            sendJson(exchange, 200, LhwJson.object("ok", true));
        else
            sendJson(exchange, 404, LhwJson.object("error", "키를 찾을 수 없습니다"));
    }

    // ── 인증·오리진 ──────────────────────────────────────────

    private boolean authorized(final HttpExchange exchange) {
        final String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer "))
            return false;
        return token.verify(header.substring("Bearer ".length()).trim());
    }

    private static boolean originAllowed(final HttpExchange exchange) {
        final String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (origin == null)
            return true;
        try {
            final URI parsed = URI.create(origin);
            final String host = parsed.getHost();
            return "http".equals(parsed.getScheme()) && host != null
                    && LOOPBACK_ORIGIN_HOSTS.contains(host.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    // ── 정적 파일 ────────────────────────────────────────────

    private void handleStatic(final HttpExchange exchange, final String rawPath) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")
                && !exchange.getRequestMethod().equalsIgnoreCase("HEAD")) {
            sendJson(exchange, 405, LhwJson.object("error", "허용되지 않은 메소드입니다"));
            return;
        }
        if (webRoot == null) {
            sendJson(exchange, 404, LhwJson.object(
                    "error", "API 전용 모드입니다. 정적 웹은 --web-dir 로 지정하세요"));
            return;
        }
        Path resolved = resolveStatic(rawPath);
        if (resolved == null || !Files.isRegularFile(resolved)) {
            // SPA 라우트 폴백: 확장자 없는 GET 은 index.html 로
            if (!rawPath.contains(".")) {
                resolved = webRoot.resolve("index.html");
            }
            if (resolved == null || !Files.isRegularFile(resolved)) {
                sendJson(exchange, 404, LhwJson.object("error", "리소스를 찾을 수 없습니다"));
                return;
            }
        }
        final String fileName = resolved.getFileName().toString();
        final String contentType = contentTypeOf(fileName);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        if (fileName.endsWith(".html")) {
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                            + "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
                            + "frame-ancestors 'none'; form-action 'self'; object-src 'none'");
        } else if (rawPath.startsWith("/assets/")) {
            // 해시 파일명이므로 불변 캐시 허용
            exchange.getResponseHeaders().set("Cache-Control", "public, max-age=31536000, immutable");
        } else {
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
        }
        final byte[] body = Files.readAllBytes(resolved);
        if (exchange.getRequestMethod().equalsIgnoreCase("HEAD")) {
            exchange.sendResponseHeaders(200, -1);
            return;
        }
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private @Nullable Path resolveStatic(final String rawPath) {
        final String relative = rawPath.equals("/") ? "index.html" : rawPath.substring(1);
        if (relative.contains("\0"))
            return null;
        final Path candidate = webRoot.resolve(relative).normalize();
        // 경로 이탈(traversal) 차단: 정규화 결과가 루트 내부여야 한다
        if (!candidate.startsWith(webRoot))
            return null;
        return candidate;
    }

    private static String contentTypeOf(final String fileName) {
        final String lower = fileName.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html")) return "text/html; charset=utf-8";
        if (lower.endsWith(".js") || lower.endsWith(".mjs")) return "text/javascript; charset=utf-8";
        if (lower.endsWith(".css")) return "text/css; charset=utf-8";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".ico")) return "image/x-icon";
        if (lower.endsWith(".json") || lower.endsWith(".map")) return "application/json; charset=utf-8";
        if (lower.endsWith(".woff2")) return "font/woff2";
        if (lower.endsWith(".txt")) return "text/plain; charset=utf-8";
        return "application/octet-stream";
    }

    // ── 공통 ────────────────────────────────────────────────

    private static void baseHeaders(final HttpExchange exchange) {
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
    }

    private static void sendJson(final HttpExchange exchange, final int status, final String json)
            throws IOException {
        final byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        if (exchange.getResponseHeaders().getFirst("Cache-Control") == null)
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static List<String> splitRoute(final String route) {
        return List.of(route.split("/", -1));
    }

    private static String requireKey(final String encoded) throws BadRequest {
        final String key = URLDecoder.decode(encoded, StandardCharsets.UTF_8).trim();
        if (key.isEmpty())
            throw new BadRequest("키 이름이 비어 있습니다");
        if (key.length() > MAX_KEY_CHARS)
            throw new BadRequest("키 이름이 너무 깁니다 (최대 " + MAX_KEY_CHARS + "자)");
        for (int i = 0; i < key.length(); i++) {
            if (key.charAt(i) < 0x20)
                throw new BadRequest("키 이름에 제어 문자를 쓸 수 없습니다");
        }
        return key;
    }

    /// 요청 형식 오류를 400 으로 매핑하는 내부 예외입니다.
    private static final class BadRequest extends Exception {
        private BadRequest(final String message) {
            super(message);
        }
    }

    /// [LhwServer] 빌더입니다.
    public static final class Builder {

        private ISSClientConfig target;
        private LhwToken token;
        private @Nullable Path webDir;
        private int httpPort = 5874;

        /// 중계 타겟 ISS 서버 접속 구성(필수)
        public @NotNull Builder target(final @NotNull ISSClientConfig target) {
            this.target = target;
            return this;
        }

        /// 접속 토큰 검증기(필수)
        public @NotNull Builder token(final @NotNull LhwToken token) {
            this.token = token;
            return this;
        }

        /// 빌드된 Angular 정적 웹 디렉터리. 미지정 시 API 전용 모드
        public @NotNull Builder webDir(final @Nullable Path webDir) {
            this.webDir = webDir;
            return this;
        }

        /// HTTP 바인드 포트 (기본 5874, 0이면 임의 포트)
        public @NotNull Builder httpPort(final int httpPort) {
            this.httpPort = httpPort;
            return this;
        }

        public @NotNull LhwServer build() throws ISSException {
            return new LhwServer(this);
        }
    }
}
