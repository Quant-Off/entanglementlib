/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.experimental.security.builder.signature;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.security.algorithm.Digest;

import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@ApiStatus.Experimental
public final class SignatureSetting {

    private final Digest pssParameterDigest;
    private final MGF1ParameterSpec mgf1Digest;
    private final int saltLength;
    private final int trailerField;

    private final PSSParameterSpec pssParameterSpec;

    SignatureSetting(Digest pssParameterDigest, MGF1ParameterSpec mgf1Digest, int saltLength, int trailerField) {
        this.pssParameterDigest = pssParameterDigest == null ? Digest.SHA3_256 : pssParameterDigest;
        this.mgf1Digest = mgf1Digest == null ? MGF1ParameterSpec.SHA256 : mgf1Digest;
        this.saltLength = Math.max(saltLength, 16);
        this.trailerField = Math.max(trailerField, 1);
        this.pssParameterSpec = new PSSParameterSpec(this.pssParameterDigest.getName(), "MGF1", this.mgf1Digest, this.saltLength, this.trailerField);
    }

    public static SignatureSettingBuilder builder() {
        return new SignatureSettingBuilder();
    }

    @NoArgsConstructor
    public static final class SignatureSettingBuilder {

        private Digest pssParameterDigest;
        private MGF1ParameterSpec mgf1Digest;
        private int saltLength;
        private int trailerField;

        public SignatureSettingBuilder pssParameterDigest(Digest pssParameterDigest) {
            this.pssParameterDigest = pssParameterDigest;
            return this;
        }

        public SignatureSettingBuilder mgf1Digest(MGF1ParameterSpec mgf1Digest) {
            this.mgf1Digest = mgf1Digest;
            return this;
        }

        public SignatureSettingBuilder saltLength(int saltLength) {
            this.saltLength = saltLength;
            return this;
        }

        public SignatureSettingBuilder trailerField(int trailerField) {
            this.trailerField = trailerField;
            return this;
        }

        public SignatureSetting done() {
            return new SignatureSetting(pssParameterDigest, mgf1Digest, saltLength, trailerField);
        }
    }
}
