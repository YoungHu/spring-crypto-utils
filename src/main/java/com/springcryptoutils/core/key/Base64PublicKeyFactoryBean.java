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
package com.springcryptoutils.core.key;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import sun.misc.BASE64Decoder;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;

/**
 * A spring bean factory for retrieving public keys from a base64 encode text.
 *
 * @author huyong (huyong5802@gmail.com)
 */
public class Base64PublicKeyFactoryBean implements FactoryBean, InitializingBean {

    private String algorithm = "RSA";
    private String file;

    private PublicKey publicKey;

    /**
     * set algorithm use the get the key factory instance
     * @param algorithm algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * set base64 encode text with contain public key
     * @param file text
     */
    public void setFile(String file) {
        this.file = file;
    }

    public Object getObject() {
        return publicKey;
    }

    public Class getObjectType() {
        return PublicKey.class;
    }

    public boolean isSingleton() {
        return true;
    }

    public void afterPropertiesSet() throws Exception {
        BASE64Decoder decoder = new BASE64Decoder();

        file = file.replaceAll("\r", "").replaceAll("\n", "").replaceAll(" ", "");
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoder.decodeBuffer(file));

        this.publicKey = keyFactory.generatePublic(spec);
    }

}
