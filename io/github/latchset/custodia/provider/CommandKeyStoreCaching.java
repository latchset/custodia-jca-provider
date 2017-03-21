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
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Hashtable;

public class CommandKeyStoreCaching extends CommandKeyStore {

	final Hashtable<String, Object> cache;

	public CommandKeyStoreCaching(Config attr) {
		super(attr);
		cache = new Hashtable<String, Object>();
	}

	protected Object getValue(String alias) {
		Object value = cache.get(alias);
		if (value == null || value instanceof String) {
			value = super.getValue(alias);
			if (value != null) {
				cache.put(alias, value);
			}
		}
		return value;
	}

	@Override
	public void engineLoad(InputStream stream, char[] password)
		throws IOException, NoSuchAlgorithmException, CertificateException {
		// System.err.println(getClass() + ".engineLoad " + stream + " " + password);

		super.engineLoad(stream, password);
		if (config.containsKey("alias")) {
			cache.put(config.get("alias"), "");
		} else if (container() != null) {
			Enumeration<String> aliases = super.engineAliases();
			while (aliases.hasMoreElements()) {
				cache.put(aliases.nextElement(), "");
			}
		}
		// System.err.println("  engineLoad -> loaded " + cache.size() + " aliases.");
	}

	@Override
	public int engineSize() {
		// System.err.println(getClass() + ".engineSize");
		int size = cache.size();
		// System.err.println("  engineSize -> " + size + ".");
		return size;
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		// System.err.println(getClass() + ".engineContainsAlias " + alias);
		boolean result = cache.containsKey(alias);
		if (!result && container() == null && alias.contains("/")) {
			// System.err.println("    will try to fetch the data for alias with /");
			result = super.engineContainsAlias(alias);
		}
		// System.err.println("  engineContainsAlias " + alias + " -> " + result + ".");
		return result;
	}

	@Override
	public Enumeration<String> engineAliases() {
		// System.err.println(getClass() + ".engineAliases");
		// System.err.println("  engineAliases -> " + cache.size() + " aliases.");
		return cache.keys();
	}

	@Override
	public void engineDeleteEntry(String alias)
		throws KeyStoreException {
		// System.err.println(getClass() + ".engineDeleteEntry " + alias);
		super.engineDeleteEntry(alias);
		cache.remove(alias);
	}

	@Override
	public void engineSetKeyEntry(String alias, Key key,
		char[] password, Certificate[] chain)
		throws KeyStoreException {
		// System.err.println(getClass() + ".engineSetKeyEntry(char[]) " + alias);
		KeyCertValue kcv = super.engineSetKeyEntryKCV(alias, key, password, chain);
		cache.put(alias, kcv);
		// System.err.println("  engineSetKeyEntry -> stored.");
	}
};
