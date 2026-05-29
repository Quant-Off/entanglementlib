package space.qu4nt.entanglementlib.iss.handler;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodecTest {

    @Test
    @DisplayName("IssRequest 인코딩/디코딩 왕복")
    void requestRoundTrip() throws Exception {
        final byte[] body = "hello".getBytes(StandardCharsets.UTF_8);
        final ISSRequest decoded = ISSRequest.decode(new ISSRequest("PUT", body).encode());

        assertThat(decoded.command()).isEqualTo("PUT");
        assertThat(decoded.body()).isEqualTo(body);
    }

    @Test
    @DisplayName("IssResponse 인코딩/디코딩 왕복 (상태 보존)")
    void responseRoundTrip() {
        final ISSResponse decoded = ISSResponse.decode(ISSResponse.notFound().encode());
        assertThat(decoded.status()).isEqualTo(ISSStatus.NOT_FOUND);

        final ISSResponse ok = ISSResponse.decode(ISSResponse.ok("data".getBytes(StandardCharsets.UTF_8)).encode());
        assertThat(ok.status()).isEqualTo(ISSStatus.OK);
        assertThat(ok.bodyAsText()).isEqualTo("data");
    }

    @Test
    @DisplayName("KvCodec 키-값 인코딩/디코딩 왕복")
    void kvRoundTrip() throws Exception {
        final byte[] value = new byte[]{1, 2, 3, 4, 5};
        final KvCodec.KeyValue kv = KvCodec.decodeKeyValue(KvCodec.encodeKeyValue("config", value));

        assertThat(kv.key()).isEqualTo("config");
        assertThat(kv.value()).isEqualTo(value);
    }

    @Test
    @DisplayName("KvCodec 키 전용 디코딩")
    void keyOnly() throws Exception {
        assertThat(KvCodec.decodeKey(KvCodec.encodeKey("alpha"))).isEqualTo("alpha");
    }

    @Test
    @DisplayName("키 길이 헤더가 본문을 초과하면 거부한다")
    void rejectsTruncatedKey() {
        assertThatThrownBy(() -> KvCodec.decodeKeyValue(new byte[]{0x00, 0x10, 0x01}))
                .isInstanceOf(ISSProtocolException.class);
    }

    @Test
    @DisplayName("빈 요청 페이로드는 거부한다")
    void rejectsEmptyRequest() {
        assertThatThrownBy(() -> ISSRequest.decode(new byte[0])).isInstanceOf(ISSProtocolException.class);
    }
}
