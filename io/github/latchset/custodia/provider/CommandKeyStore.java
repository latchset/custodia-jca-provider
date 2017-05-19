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

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Scanner;

public class CommandKeyStore extends KeyStoreSpi {

	final Config config;

	static class Config extends Hashtable<String, String> {
		Config(Hashtable<String, String> orig) {
			for (String k : orig.keySet()) {
				super.put(k, orig.get(k));
			}
		}
		Config(String arg) {
			super();
			if (arg != null) {
				try {
					loadStream(new FileInputStream(arg));
					put("config-file", arg);
				} catch (FileNotFoundException e) {
				}
			}
		}
		void loadStream(InputStream in) {
			Scanner s = new Scanner(in);
			while (s.hasNextLine()) {
				if (s.findInLine("(^|\\G)\\s*(name|container|command(|-get|-set|-del|-aliases)|caching):\\s*") != null) {
					super.put(s.match().group(2), s.nextLine());
				} else if (s.findInLine("(^|\\G)\\s*(slot|alias):\\s*") != null) {
					String alias = s.nextLine();
					Pattern p = Pattern.compile("\\$\\{ENV:(.+?)\\}");
					Matcher m = p.matcher(alias);
					if (m.matches()) {
						alias = System.getenv(m.group(1));
					}
					super.put("alias", alias);
				} else {
					String skip = s.nextLine();
					// System.err.println("  skipping line " + skip);
				}
			}
		}
		String id() {
			if (super.containsKey("name")) {
				return super.get("name");
			} else if (super.containsKey("container")) {
				return super.get("container");
			} else {
				return null;
			}
		}
		String id(String id) {
			String sub = id();
			if (sub != null) {
				return id + "-" + sub;
			} else {
				return id;
			}
		}
	};

	String expandVariables(Pattern p, String input, String alias, String value) {
		String x = input;
		int start = 0;
		while (start < x.length()) {
			Matcher m = p.matcher(x);
			if (m.find(start)) {
				String replace = "";
				if (m.group(1).equals("value")) {
					replace = value;
				} else if (m.group(1).equals("alias") && alias != null) {
					replace = alias;
				} else if (config.containsKey(m.group(1))) {
					replace = config.get(m.group(1)) + m.group(2);
				}
				start = m.start() + replace.length();
				x = x.substring(0, m.start()) + replace + x.substring(m.end());
			} else {
				break;
			}
		}
		return x;
	}
	String[] expandVariables(String[] input, String alias, String value) {
		Pattern p = Pattern.compile("\\$\\{(.+?)(/?)\\}");
		ArrayList<String> result = new ArrayList<String>();
		for (int i = 0; i < input.length; i++) {
			if (input[i].equals("${command}")) {
				// We treat command as space-separated list
				result.addAll(Arrays.asList(config.get("command").split(" ")));
			} else {
				result.add(expandVariables(p, input[i], alias, value));
			}
		}
		return result.toArray(new String[result.size()]);
	}
	String[] expandVariables(String[] input, String alias) {
		return expandVariables(input, alias, null);
	}

	public CommandKeyStore(Config attr) {
		config = new Config(attr);
	}

	protected String container() {
		return config.get("container");
	}

	private Object retrieveValue(InputStream stream) {
		// System.err.println("  retrieveValue from stream");
		KeyCertValue kcv = utilReadPEM.readPEMStream(stream);

		if (kcv.key == null && kcv.encryptedKey == null) {
			if (kcv.chain.length > 0) {
				return kcv.chain[0];
			} else {
				return null;
			}
		} else {
			return kcv;
		}
	}

	protected Object getValue(String alias) {
		Object value = null;
		if (config.containsKey("command-get")) {
			String[] commands = expandVariables(config.get("command-get").split(" "), alias);
			Runtime runtime = Runtime.getRuntime();
			try {
				Process proc = runtime.exec(commands);
				proc.getOutputStream().close();
				try {
					proc.waitFor();
					value = retrieveValue(proc.getInputStream());
				} catch (InterruptedException e) {
					// System.err.println(e);
				}
			} catch (IOException e) {
				// System.err.println(e);
			}
		}
		return value;
	}

	@Override
	public void engineLoad(InputStream stream, char[] password)
		throws IOException, NoSuchAlgorithmException, CertificateException {
		// System.err.println(getClass() + ".engineLoad " + stream + " " + password);

		if (stream != null) {
			config.loadStream(stream);
		}
		if (password != null) {
			config.put("keystore-password", new String(password));
		}
		// System.err.println("  engineLoad.");
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
		throws IOException, NoSuchAlgorithmException, CertificateException {
		// System.err.println(getClass() + ".engineStore");
		// We store the values already in engineSetKeyEntry.
		return;
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		// System.err.println(getClass() + ".engineGetCertificateAlias");
		return null;
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		// System.err.println(getClass() + ".engineIsCertificateEntry " + alias);
		Object value = getValue(alias);
		boolean result = value instanceof Certificate ? true : false;
		// System.err.println("  engineIsCertificateEntry " + alias + " -> " + result + ".");
		return result;
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		// System.err.println(getClass() + ".engineIsKeyEntry " + alias);
		Object value = getValue(alias);
		boolean result = value instanceof KeyCertValue ? true : false;
		// System.err.println("  engineIsKeyEntry " + alias + " -> " + result + ".");
		return result;
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		// System.err.println(getClass() + ".engineContainsAlias " + alias);
		boolean result = getValue(alias) != null;
		// System.err.println("  engineContainsAlias " + alias + " -> " + result + ".");
		return result;
	}

	private ArrayList<String> engineAliasesArray() {
		ArrayList<String> aliases = new ArrayList<String>();
		if (config.containsKey("alias")) {
			aliases.add(config.get("alias"));
		} else if (container() != null) {
			String[] commands = expandVariables(config.get("command-aliases").split(" "), null);
			Runtime runtime = Runtime.getRuntime();
			try {
				Process proc = runtime.exec(commands);
				proc.getOutputStream().close();
				Scanner scanner = new Scanner(proc.getInputStream());
				while (scanner.hasNextLine()) {
					aliases.add(scanner.nextLine());
				}
				proc.waitFor();
			} catch (InterruptedException | IOException e) {
			}
		}
		return aliases;
	}
	@Override
	public Enumeration<String> engineAliases() {
		// System.err.println(getClass() + ".engineAliases");
		ArrayList<String> aliases = engineAliasesArray();
		// System.err.println("  engineAliases -> " + aliases.size() + " aliases.");
		return Collections.enumeration(aliases);
	}

	@Override
	public int engineSize() {
		// System.err.println(getClass() + ".engineSize");
		ArrayList<String> aliases = engineAliasesArray();
		int size = aliases.size();
		// System.err.println("  engineSize -> " + size + ".");
		return size;
	}

	private void deleteEntry(String alias, boolean throwException)
		throws KeyStoreException {
		String[] commands = expandVariables(config.get("command-del").split(" "), alias);
		try {
			Runtime runtime = Runtime.getRuntime();
			runtime.exec(commands).waitFor();
		} catch (IOException | InterruptedException e) {
			if (throwException) {
				// System.err.println("Failed");
				throw new KeyStoreException(e.toString());
			}
		}
	}
	@Override
	public void engineDeleteEntry(String alias)
		throws KeyStoreException {
		// System.err.println(getClass() + ".engineDeleteEntry " + alias);
		deleteEntry(alias, true);
	}

	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert)
		throws KeyStoreException {
		// System.err.println(getClass() + ".engineSetCertificateEntry " + alias);
		Certificate[] chain = { cert };
		engineSetKeyEntry(alias, null, null, chain);
	}

	protected KeyCertValue engineSetKeyEntryKCV(String alias, Key key,
		char[] password, Certificate[] chain)
		throws KeyStoreException {
		byte[] encryptedKey = null;
		if (key != null && key instanceof PrivateKey && password != null) {
			encryptedKey = utilEncryptDecrypt.encrypt((PrivateKey)key, password);
			key = null;
		}

		KeyCertValue kcv = new KeyCertValue(key, encryptedKey, chain);
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		utilWritePEM.writeAsPEM(buffer, kcv);

		deleteEntry(alias, false);
		String[] commands = expandVariables(config.get("command-set").split(" "), alias, buffer.toString());
		try {
			Runtime runtime = Runtime.getRuntime();
			runtime.exec(commands).waitFor();
		} catch (IOException | InterruptedException e) {
			// System.err.println("Failed");
			throw new KeyStoreException(e.toString());
		}
		return kcv;
	}
	@Override
	public void engineSetKeyEntry(String alias, Key key,
		char[] password, Certificate[] chain)
		throws KeyStoreException {
		// System.err.println(getClass() + ".engineSetKeyEntry(char[]) " + alias);
		engineSetKeyEntryKCV(alias, key, password, chain);
		// System.err.println("  engineSetKeyEntry -> stored.");
	}

	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
		throws KeyStoreException {
		// System.err.println(getClass() + ".engineSetKeyEntry(byte[]) " + alias);
		throw new KeyStoreException("engineSetKeyEntry encrypted not supported (FIXME).");
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		// System.err.println(getClass() + ".engineGetCreationDate " + alias);
		return null;
	}

	@Override
	public Certificate engineGetCertificate(String alias) {
		// System.err.println(getClass() + ".engineGetCertificate " + alias);
		Object value = getValue(alias);
		if (value instanceof KeyCertValue && ((KeyCertValue)value).chain.length > 0) {
			return ((KeyCertValue)value).chain[0];
		}
		// System.err.println("  engineGetCertificate -> null.");
		return null;
	}

	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		// System.err.println(getClass() + ".engineGetCertificateChain " + alias);
		Object value = getValue(alias);
		if (value instanceof KeyCertValue) {
			// System.err.println("  engineGetCertificateChain -> " + ((KeyCertValue)value).chain.length + " certificates in chain.");
			return ((KeyCertValue)value).chain;
		}
		// System.err.println("  engineGetCertificateChain -> null.");
		return null;
	}

	@Override
	public Key engineGetKey(String alias, char[] password)
		throws NoSuchAlgorithmException, UnrecoverableKeyException {
		// System.err.println(getClass() + ".engineGetKey " + alias);
		Object value = getValue(alias);
		if (value instanceof KeyCertValue) {
			if (((KeyCertValue)value).key != null) {
				// System.err.println("  engineGetKey -> " + ((KeyCertValue)value).key.getClass() + ".");
				return ((KeyCertValue)value).key;
			}
			if (password == null && config.containsKey("keystore-password")) {
				// System.err.println("  using keystore password");
				password = config.get("keystore-password").toCharArray();
			}
			if (password != null) {
				return utilEncryptDecrypt.decrypt(((KeyCertValue)value).encryptedKey, new String(password));
			}
			// System.err.println("  no password specified.");
		}
		// System.err.println("  engineGetKey -> null.");
		return null;
	}
};
