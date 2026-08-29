/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.cli;

import space.qu4nt.entanglementlib.iss.ISS;
import space.qu4nt.entanglementlib.iss.ISSClient;
import space.qu4nt.entanglementlib.iss.ISSClientConfig;
import space.qu4nt.entanglementlib.iss.ISSServer;
import space.qu4nt.entanglementlib.iss.exception.ISSException;
import space.qu4nt.entanglementlib.iss.internal.SDCBytes;
import space.qu4nt.entanglementlib.iss.security.BindPolicy;
import space.qu4nt.entanglementlib.iss.security.ISSPSK;
import space.qu4nt.entanglementlib.iss.web.LhwServer;
import space.qu4nt.entanglementlib.iss.web.LhwToken;
import space.qu4nt.entanglementlib.security.crypto.rng.RNG;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

/// 폐쇄망 내부 공유 서버(ISS) 명령행 도구입니다.
///
/// 서브커맨드: serve, ping, put, get, del, list, status, gen-psk, lhw. PSK는 평문 인자로 받지
/// 않고 파일(`--psk-file`) 또는 환경변수(`--psk-env`, hex)로만 받습니다.
///
/// @author Q. T. Felix
public final class ISSCLI {

    private static final String VERSION = "2.0.0";
    private static final Set<String> BOOLEAN_FLAGS = Set.of("--stdin", "--allow-nonloopback");

    private ISSCLI() {
        throw new UnsupportedOperationException("cannot access");
    }

    public static void main(final String[] args) {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printHelp();
            return;
        }
        if (args[0].equals("--version") || args[0].equals("-v")) {
            System.out.println("iss " + VERSION);
            return;
        }

        final String command = args[0];
        final Args parsed = Args.parse(args, 1);
        try {
            switch (command) {
                case "serve" -> serve(parsed);
                case "ping" -> ping(parsed);
                case "put" -> put(parsed);
                case "get" -> get(parsed);
                case "del" -> del(parsed);
                case "list" -> list(parsed);
                case "status" -> status(parsed);
                case "gen-psk" -> genPsk(parsed);
                case "lhw" -> lhw(parsed);
                default -> {
                    System.err.println("알 수 없는 명령입니다: " + command);
                    printHelp();
                    System.exit(2);
                }
            }
        } catch (CliExit e) {
            System.exit(e.code);
        } catch (Exception e) {
            System.err.println("오류: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void serve(final Args args) throws ISSException, InterruptedException {
        ISS.initializeVerified();
        final int port = args.requireInt("--port");
        final String bind = args.get("--bind", "127.0.0.1");

        final SensitiveDataContainer psk = loadPsk(args);
        final ISSServer.Builder builder = ISSServer.builder()
                .bindHost(bind)
                .port(port)
                .psk(psk)
                .allowNonLoopback(args.has("--allow-nonloopback"));
        if (args.has("--max-conn"))
            builder.maxConnections(args.requireInt("--max-conn"));
        for (final String peer : args.getAll("--allow-peer"))
            builder.allowPeer(BindPolicy.resolve(peer));

        final ISSServer server = builder.build();
        final CountDownLatch latch = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            psk.close();
            latch.countDown();
        }));

        server.start();
        System.out.println("ISS 서버 실행 중 " + bind + ":" + server.port() + " (Ctrl-C 로 종료)");
        latch.await();
    }

    private static void ping(final Args args) throws Exception {
        withClient(args, client -> {
            client.ping();
            System.out.println("OK (pong)");
        });
    }

    private static void put(final Args args) throws Exception {
        final String key = args.require("--key");
        final byte[] value = resolveValue(args);
        withClient(args, client -> {
            client.put(key, value);
            System.out.println("OK");
        });
    }

    private static void get(final Args args) throws Exception {
        final String key = args.require("--key");
        withClient(args, client -> {
            final byte[] value = client.get(key);
            if (value == null) {
                System.err.println("(없음)");
                throw new CliExit(1);
            }
            if (args.has("--out")) {
                writeFile(Path.of(args.get("--out", null)), value);
                System.out.println("OK (" + value.length + " 바이트 저장)");
            } else {
                System.out.write(value);
                System.out.flush();
            }
        });
    }

    private static void del(final Args args) throws Exception {
        final String key = args.require("--key");
        withClient(args, client -> {
            final boolean existed = client.delete(key);
            System.out.println(existed ? "OK" : "(없음)");
            if (!existed)
                throw new CliExit(1);
        });
    }

    private static void list(final Args args) throws Exception {
        withClient(args, client -> {
            for (final String key : client.list())
                System.out.println(key);
        });
    }

    private static void status(final Args args) throws Exception {
        withClient(args, client -> System.out.println(client.status()));
    }

    private static void genPsk(final Args args) throws Exception {
        ISS.initializeVerified();
        final int bytes = args.has("--bytes") ? args.requireInt("--bytes") : 32;
        if (bytes < 32)
            throw new ISSException("PSK 길이는 최소 32바이트여야 합니다");

        try (SDCScopeContext scope = new SDCScopeContext()) {
            final SensitiveDataContainer random = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, bytes);
            final byte[] raw = SDCBytes.export(random);
            try {
                if (args.has("--out")) {
                    final Path out = Path.of(args.get("--out", null));
                    writeFile(out, raw);
                    restrictPermissions(out);
                    System.out.println("PSK " + bytes + "바이트를 생성했습니다: " + out);
                } else {
                    System.out.println(toHex(raw));
                }
            } finally {
                java.util.Arrays.fill(raw, (byte) 0);
            }
        }
    }

    private static void lhw(final Args args) throws Exception {
        ISS.initializeVerified();
        final int port = args.requireInt("--port");
        final String host = args.get("--host", "127.0.0.1");
        final int httpPort = args.has("--http-port") ? args.requireInt("--http-port") : 5874;
        final Path webDir = args.has("--web-dir") ? Path.of(args.get("--web-dir", null)) : null;

        final SensitiveDataContainer psk = loadPsk(args);
        final ISSClientConfig target = ISSClientConfig.builder()
                .host(host)
                .port(port)
                .psk(psk)
                .build();
        final LhwToken.Issued issued = LhwToken.issue();
        final LhwServer server = LhwServer.builder()
                .target(target)
                .token(issued.verifier())
                .webDir(webDir)
                .httpPort(httpPort)
                .build();

        final CountDownLatch latch = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            psk.close();
            latch.countDown();
        }));

        server.start();
        System.out.println("LHW 브리지 실행 중 http://127.0.0.1:" + server.port()
                + " -> ISS " + host + ":" + port + " (Ctrl-C 로 종료)");
        System.out.println("접속 토큰(1회 표시): " + issued.tokenHex());
        if (webDir == null)
            System.out.println("정적 웹 미지정(--web-dir). API 전용 모드로 동작합니다.");
        try (ISSClient probe = ISSClient.connect(target)) {
            probe.ping();
            System.out.println("타겟 ISS 서버 응답 확인(pong)");
        } catch (Exception e) {
            System.out.println("경고: 타겟 ISS 서버에 아직 연결할 수 없습니다 -> " + e.getMessage());
        }
        latch.await();
    }

    private static void withClient(final Args args, final ClientAction action) throws Exception {
        ISS.initializeVerified();
        final SensitiveDataContainer psk = loadPsk(args);
        try (psk; ISSClient client = ISSClient.connect(ISSClientConfig.builder()
                .host(args.get("--host", "127.0.0.1"))
                .port(args.requireInt("--port"))
                .psk(psk)
                .build())) {
            action.run(client);
        }
    }

    private static SensitiveDataContainer loadPsk(final Args args) throws ISSException {
        if (args.has("--psk-file"))
            return ISSPSK.fromFile(Path.of(args.get("--psk-file", null)));
        if (args.has("--psk-env"))
            return ISSPSK.fromEnv(args.get("--psk-env", null));
        throw new ISSException("PSK 소스가 필요합니다 (--psk-file <경로> 또는 --psk-env <변수명>)");
    }

    private static byte[] resolveValue(final Args args) throws Exception {
        if (args.has("--stdin"))
            return readAll(System.in);
        if (args.has("--value-file"))
            return Files.readAllBytes(Path.of(args.get("--value-file", null)));
        if (args.has("--value"))
            return args.get("--value", "").getBytes(StandardCharsets.UTF_8);
        throw new ISSException("값 소스가 필요합니다 (--value, --value-file, 또는 --stdin)");
    }

    private static byte[] readAll(final InputStream in) throws IOException {
        return in.readAllBytes();
    }

    private static void writeFile(final Path path, final byte[] data) throws IOException {
        Files.write(path, data);
    }

    private static void restrictPermissions(final Path path) {
        try {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException ignored) {
            // POSIX 미지원 파일시스템에서는 무시
        }
    }

    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder(data.length * 2);
        for (final byte b : data)
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        return sb.toString();
    }

    private static void printHelp() {
        System.out.println("""
                iss - 폐쇄망 내부 공유 서버 (EntanglementLib)

                사용법:
                  iss serve   --port N [--bind 127.0.0.1] (--psk-file F | --psk-env VAR)
                              [--max-conn 64] [--allow-nonloopback] [--allow-peer IP]...
                  iss ping    --port N [--host 127.0.0.1] (--psk-file F | --psk-env VAR)
                  iss put     --port N [--host H] (--psk-file F | --psk-env VAR)
                              --key K (--value V | --value-file F | --stdin)
                  iss get     --port N [--host H] (--psk-file F | --psk-env VAR) --key K [--out FILE]
                  iss del     --port N [--host H] (--psk-file F | --psk-env VAR) --key K
                  iss list    --port N [--host H] (--psk-file F | --psk-env VAR)
                  iss status  --port N [--host H] (--psk-file F | --psk-env VAR)
                  iss gen-psk [--bytes 32] [--out FILE]
                  iss lhw     --port N [--host 127.0.0.1] (--psk-file F | --psk-env VAR)
                              [--http-port 5874] [--web-dir DIR]
                  iss --help | --version

                PSK는 평문 인자로 받지 않습니다. 파일(raw 바이트) 또는 환경변수(hex)로만 입력합니다.
                """);
    }

    /// CLI 종료 코드를 전달하는 내부 제어 예외입니다.
    private static final class CliExit extends RuntimeException {
        final int code;

        CliExit(final int code) {
            this.code = code;
        }
    }

    @FunctionalInterface
    private interface ClientAction {
        void run(ISSClient client) throws Exception;
    }

    /// 경량 명령행 인자 파서입니다.
    private static final class Args {

        private final Map<String, List<String>> values = new HashMap<>();

        static Args parse(final String[] argv, final int from) {
            final Args args = new Args();
            int i = from;
            while (i < argv.length) {
                final String token = argv[i];
                if (token.startsWith("--")) {
                    if (BOOLEAN_FLAGS.contains(token)) {
                        args.add(token, "true");
                        i++;
                    } else if (i + 1 < argv.length) {
                        args.add(token, argv[i + 1]);
                        i += 2;
                    } else {
                        args.add(token, "");
                        i++;
                    }
                } else {
                    i++;
                }
            }
            return args;
        }

        private void add(final String key, final String value) {
            values.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        }

        boolean has(final String key) {
            return values.containsKey(key);
        }

        String get(final String key, final String defaultValue) {
            final List<String> list = values.get(key);
            return (list == null || list.isEmpty()) ? defaultValue : list.getFirst();
        }

        String require(final String key) throws ISSException {
            if (!has(key))
                throw new ISSException("필수 인자 누락: " + key);
            return get(key, null);
        }

        int requireInt(final String key) throws ISSException {
            try {
                return Integer.parseInt(require(key));
            } catch (NumberFormatException e) {
                throw new ISSException("정수 인자가 올바르지 않습니다: " + key);
            }
        }

        List<String> getAll(final String key) {
            return values.getOrDefault(key, List.of());
        }
    }
}
