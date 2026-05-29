package space.qu4nt.entanglementlib.iss.protocol;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FrameHeaderTest {

    @Test
    @DisplayName("헤더 인코딩 후 디코딩하면 동일한 필드를 복원한다")
    void encodeDecodeRoundTrip() throws Exception {
        final FrameHeader header = new FrameHeader(Opcode.DATA, (byte) 0, 7L, 1024);
        final FrameHeader decoded = FrameHeader.decode(header.encode());

        assertThat(decoded.opcode()).isEqualTo(Opcode.DATA);
        assertThat(decoded.seq()).isEqualTo(7L);
        assertThat(decoded.cipherLen()).isEqualTo(1024);
    }

    @Test
    @DisplayName("잘못된 MAGIC 헤더는 거부한다")
    void rejectsBadMagic() {
        final byte[] header = new FrameHeader(Opcode.DATA, (byte) 0, 0L, 64).encode();
        header[0] ^= 0xFF;
        assertThatThrownBy(() -> FrameHeader.decode(header)).isInstanceOf(ISSProtocolException.class);
    }

    @Test
    @DisplayName("cipher_len 이 최대 프레임을 초과하면 거부한다")
    void rejectsOversizeCipherLen() {
        final byte[] header = craft(Opcode.DATA.code(), 0L, WireConstants.MAX_FRAME + 1);
        assertThatThrownBy(() -> FrameHeader.decode(header)).isInstanceOf(ISSProtocolException.class);
    }

    @Test
    @DisplayName("부호 없는 cipher_len(0xFFFFFFFF)도 경계 검사로 거부한다")
    void rejectsUnsignedHugeCipherLen() {
        final byte[] header = craft(Opcode.DATA.code(), 0L, 0xFFFFFFFF);
        assertThatThrownBy(() -> FrameHeader.decode(header)).isInstanceOf(ISSProtocolException.class);
    }

    @Test
    @DisplayName("cipher_len 이 태그 길이 미만이면 거부한다")
    void rejectsTooSmallCipherLen() {
        final byte[] header = craft(Opcode.DATA.code(), 0L, WireConstants.TAG_LEN - 1);
        assertThatThrownBy(() -> FrameHeader.decode(header)).isInstanceOf(ISSProtocolException.class);
    }

    @Test
    @DisplayName("알 수 없는 opcode 는 거부한다")
    void rejectsUnknownOpcode() {
        final byte[] header = craft((byte) 0x7F, 0L, 64);
        assertThatThrownBy(() -> FrameHeader.decode(header)).isInstanceOf(ISSProtocolException.class);
    }

    private static byte[] craft(final byte opcode, final long seq, final int cipherLen) {
        final ByteBuffer buf = ByteBuffer.allocate(WireConstants.HEADER_LEN);
        buf.putInt(WireConstants.MAGIC);
        buf.put(WireConstants.VERSION);
        buf.put(opcode);
        buf.put((byte) 0);
        buf.putLong(seq);
        buf.putInt(cipherLen);
        return buf.array();
    }
}
