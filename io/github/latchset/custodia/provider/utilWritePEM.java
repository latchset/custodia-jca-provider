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
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

public class utilWritePEM {
	static void writeAsPEM (OutputStream stream, KeyCertValue value) {
		if (value.chain != null && value.chain.length > 0) {
			for (int i = 0; i < value.chain.length; i++) {
				try {
					stream.write("-----BEGIN CERTIFICATE-----\n".getBytes());
					stream.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(value.chain[i].getEncoded()));
					stream.write("\n-----END CERTIFICATE-----\n".getBytes());
				} catch (CertificateEncodingException | IOException e) {
					// System.err.println(e);
				}
			}
		}
		if (value.key != null) {
			try {
				stream.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
				stream.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(value.key.getEncoded()));
				stream.write("\n-----END PRIVATE KEY-----\n".getBytes());
			} catch (IOException e) {
				// System.err.println(e);
			}
		}
		if (value.encryptedKey != null) {
			try {
				stream.write("-----BEGIN ENCRYPTED PRIVATE KEY-----\n".getBytes());
				stream.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(value.encryptedKey));
				stream.write("\n-----END ENCRYPTED PRIVATE KEY-----\n".getBytes());
			} catch (IOException e) {
				// System.err.println(e);
			}
		}
	}
};
