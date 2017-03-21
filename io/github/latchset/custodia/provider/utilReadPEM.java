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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.PrivateKey;
import java.util.ArrayList;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

public class utilReadPEM {
	static KeyCertValue readPEMStream(InputStream stream) {
		PrivateKey key = null;
		byte[] encryptedKey = null;
		ArrayList<Certificate> chain = new ArrayList<Certificate>();

		PEMParser keyReader = new PEMParser(new InputStreamReader(stream));
		while (true) {
			Object o = null;
			try {
				o = keyReader.readObject();
			} catch (IOException e) {
				// System.err.println(e);
			}
			if (o == null) {
				break;
			}
			if (o instanceof X509CertificateHolder) {
				try {
					chain.add(new JcaX509CertificateConverter().getCertificate((X509CertificateHolder)o));
				} catch (CertificateException e) {
					// System.err.println(e);
				}
			} else if (o instanceof PrivateKeyInfo) {
				try {
					key = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo)o);
				} catch (PEMException e) {
					// System.err.println(e);
				}
			} else if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
				try {
					encryptedKey = ((PKCS8EncryptedPrivateKeyInfo)o).getEncoded();
				} catch (IOException e) {
					// System.err.println(e);
				}
			}
		}
		Certificate[] cchain = new Certificate[chain.size()];
		cchain = chain.toArray(cchain);
		return new KeyCertValue(key, encryptedKey, cchain);
	}
};
