/*
 * Copyright 2012 Mirko Caserta
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this software except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.springcryptoutils.core.signature;

/**
 * An interface for verifying the authenticity of messages using digital signatures.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Verifier {

    /**
     * Verifies the authenticity of a message using a digital signature.
     *
     * @param message   the original message to verify
     * @param signature the digital signature
     * @return true if the original message is verified by the digital signature
     */
    boolean verify(byte[] message, byte[] signature);

}