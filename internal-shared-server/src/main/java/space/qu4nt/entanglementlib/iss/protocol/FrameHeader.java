/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.protocol;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/// 평문 레코드 헤더(19바이트)의 직렬화 및 파싱을 담당합니다.
///
/// 파싱은 어떤 버퍼 할당보다 먼저 수행되며, `cipher_len`을 부호 없는(unsigned) 값으로 해석한 뒤
/// 경계를 검증합니다. 이는 원격 메모리 고갈(음수 배열 길이, 과대 할당)을 차단합니다.
///
/// @param opcode    레코드 종류
/// @param flags     예약 플래그 (AAD에 바인딩됨)
/// @param seq       방향별 단조 증가 시퀀스 번호
/// @param cipherLen 본문 암호문 길이 (평문 길이 + 태그 16바이트)
/// @author Q. T. Felix
public record FrameHeader(@NotNull Opcode opcode, byte flags, long seq, int cipherLen) {

    /// 헤더를 19바이트 빅엔디언 표현으로 직렬화합니다.
    public byte @NotNull [] encode() {
        final ByteBuffer buf = ByteBuffer.allocate(WireConstants.HEADER_LEN);
        buf.putInt(WireConstants.MAGIC);
        buf.put(WireConstants.VERSION);
        buf.put(opcode.code());
        buf.put(flags);
        buf.putLong(seq);
        buf.putInt(cipherLen);
        return buf.array();
    }

    /// 수신한 19바이트 헤더를 파싱하고 무결성을 검증합니다.
    ///
    /// @throws ISSProtocolException MAGIC/VERSION 불일치 또는 `cipher_len` 경계 위반 시
    public static @NotNull FrameHeader decode(final byte @NotNull [] header) throws ISSProtocolException {
        if (header.length != WireConstants.HEADER_LEN)
            throw new ISSProtocolException("헤더 길이가 올바르지 않습니다");

        final ByteBuffer buf = ByteBuffer.wrap(header);
        final int magic = buf.getInt();
        if (magic != WireConstants.MAGIC)
            throw new ISSProtocolException("프로토콜 식별자가 일치하지 않습니다");

        final byte version = buf.get();
        if (version != WireConstants.VERSION)
            throw new ISSProtocolException("지원하지 않는 프로토콜 버전입니다");

        final Opcode opcode = Opcode.from(buf.get());
        final byte flags = buf.get();
        final long seq = buf.getLong();

        // 부호 없는 해석 후 경계 검증 (할당 이전)
        final long cipherLen = Integer.toUnsignedLong(buf.getInt());
        if (cipherLen < WireConstants.TAG_LEN || cipherLen > WireConstants.MAX_FRAME)
            throw new ISSProtocolException("레코드 본문 길이가 허용 범위를 벗어났습니다");

        return new FrameHeader(opcode, flags, seq, (int) cipherLen);
    }

    /// 채널에서 정확히 `buffer.remaining()` 바이트를 모두 읽을 때까지 반복합니다.
    /// 부분 읽기(short read)는 NIO에서 정상이므로 반드시 드레인 루프가 필요합니다.
    ///
    /// @throws ISSProtocolException 상대가 데이터를 마치기 전에 스트림을 닫은 경우(트렁케이션)
    public static void readFully(final @NotNull ReadableByteChannel channel, final @NotNull ByteBuffer buffer)
            throws ISSProtocolException {
        while (buffer.hasRemaining()) {
            final int n;
            try {
                n = channel.read(buffer);
            } catch (IOException e) {
                throw new ISSProtocolException("채널 읽기 실패", e);
            }
            if (n < 0)
                throw new ISSProtocolException("상대가 레코드 수신 도중 연결을 종료했습니다 (트렁케이션)");
        }
    }

    /// 채널에 버퍼의 모든 바이트를 기록할 때까지 반복합니다.
    public static void writeFully(final @NotNull WritableByteChannel channel, final @NotNull ByteBuffer buffer)
            throws ISSProtocolException {
        while (buffer.hasRemaining()) {
            try {
                channel.write(buffer);
            } catch (IOException e) {
                throw new ISSProtocolException("채널 쓰기 실패", e);
            }
        }
    }
}
