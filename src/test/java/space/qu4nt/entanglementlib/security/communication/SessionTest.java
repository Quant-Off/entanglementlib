/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.session.EntLibSessionException;
import space.qu4nt.entanglementlib.exception.session.EntLibSessionIllegalStateException;
import space.qu4nt.entanglementlib.security.communication.session.*;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

@Slf4j
class SessionTest {

    @Test
    @DisplayName("경량형 세션 테스트")
    void lightweightSessionTest() throws EntLibSessionException, IOException, EntLibSessionIllegalStateException {
        final Session session = Session.create("test-s1", SessionConfig.defaults());
        session.addEventListener(new SessionEventListener() {
            @Override
            public void onParticipantJoined(Session session, Participant participant) {
                log.info("테스트: 세션: {}, 참여자: {}", session.getSessionId(), participant.getId());
            }
        });

        SessionSecurityContext sessionSecurityContext = new SessionSecurityContext();
        sessionSecurityContext.initialize(
                new SensitiveDataContainer("This-is-master-key".getBytes(StandardCharsets.UTF_8), false),
                new SensitiveDataContainer(SensitiveDataContainer.generateSafeRandomBytes(16), false),
                KEMType.X25519MLKEM768,
                SignatureType.ML_DSA_65,
                false
        );
        session.setSessionSecurityContext(sessionSecurityContext);

        Participant p1 = new Participant("part-1", ParticipantRole.OBSERVER, SocketChannel.open(), 0, null);
        Participant p2 = new Participant("part-2", ParticipantRole.OBSERVER, SocketChannel.open(), 0, null);

        session.addParticipant(p1);

        session.activate();

        session.addParticipant(p2);

        log.info("session: {}", session);
    }
}