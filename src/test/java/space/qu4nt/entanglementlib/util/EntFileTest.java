/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.algorithm.Digest;
import space.qu4nt.entanglementlib.util.io.EntFile;
import space.qu4nt.entanglementlib.util.io.Hash;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

class EntFileTest {

    @Test
    @Order(1)
    @Disabled
    void getHashTest() throws Exception {
        // 3-256: 8876758120edda0522ffbc4dfcad9b4ad1094c16f8138a128b73136e1db04fae (64)
        // 3-512: e0d69e5835cc5400b812d80eb6bd8dc9a0522d119d45e86b6515d669dfc916edafa1c71d5e7d11611cf9f5e5cd0d9ca34de542778481b3ea45597e2b51131942 (128)
        String v3256 = Hash.hashFile(Paths.get(System.getenv("CALLER_BASE_DIR") + "/str.txt"), Digest.SHA3_256);
        String v3512 = Hash.hashFile(Paths.get(System.getenv("CALLER_BASE_DIR") + "/str.txt"), Digest.SHA3_512);
        System.out.println("SHA3_256 hash: " + v3256);
        System.out.println("SHA3_512 hash: " + v3512);
    }

    @Test
    void saveTest() throws IOException {
        byte[] str = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        long start = System.currentTimeMillis();
        String hex = EntFile.saveFileSafely("str.txt", str, false);
        long end = System.currentTimeMillis() - start;
        System.out.println(end + " / " + hex);
    }

    @Test
    @Order(2)
    @Disabled
    void loadTest() throws IOException {
        InputStream loaded = EntFile.openStreamSafelyExpectedHash("str.txt", "8876758120edda0522ffbc4dfcad9b4ad1094c16f8138a128b73136e1db04fae");
        System.out.println(new String(loaded.readAllBytes()));
        loaded.close();
    }

}