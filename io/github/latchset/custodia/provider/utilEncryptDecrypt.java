/*
 * Copyright 2017 Jan Pazdziora
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.latchset.custodia.provider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemGenerationException;

class utilEncryptDecrypt {
	static byte[] encrypt(PrivateKey key, char[] passphrase) {
		JceOpenSSLPKCS8EncryptorBuilder eb = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC);
		java.security.Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		eb.setProvider(BC);
		eb.setRandom(new SecureRandom());
		eb.setPasssword(passphrase);
		try {
			OutputEncryptor oe = eb.build();
			JcaPKCS8Generator gen = new JcaPKCS8Generator(key, oe);
			return gen.generate().getContent();
		} catch (PemGenerationException | OperatorCreationException e) {
			// System.err.println(e);
		}
		return null;
	}
	static PrivateKey decrypt(byte[] key, String passphrase) {
		JceOpenSSLPKCS8DecryptorProviderBuilder db = new JceOpenSSLPKCS8DecryptorProviderBuilder();
		java.security.Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		db.setProvider(BC);
		try {
			InputDecryptorProvider d = db.build(passphrase.toCharArray());
			PrivateKeyInfo pki = (new PKCS8EncryptedPrivateKeyInfo(key)).decryptPrivateKeyInfo(d);
			return new JcaPEMKeyConverter().getPrivateKey(pki);
		} catch (IOException | OperatorCreationException | PKCSException e) {
			// System.err.println(e);
		}
		return null;
	}
};
