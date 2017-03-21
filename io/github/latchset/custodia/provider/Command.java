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

import java.lang.reflect.Constructor;
import java.security.Provider;
import java.util.List;

public class Command extends Provider {

	private static final long serialVersionUID = 1882931045627837730L;

	protected class CommandService extends Provider.Service {
		CommandKeyStore.Config attr;
		String keyStoreClass;
		CommandService(Provider provider, String type, String algorithm,
			String className, List<String> aliases,
			CommandKeyStore.Config attributes) {
			super(provider, type, algorithm, className, aliases, attributes);
			attr = (CommandKeyStore.Config)attributes;
			keyStoreClass = className;
		}
		public Object newInstance(Object constructorParameter) {
			try {
				Class<?> c = Class.forName(keyStoreClass);
				Constructor<?> constructor = c.getConstructor(CommandKeyStore.Config.class);
				return constructor.newInstance(new Object[] { attr });
			} catch (Exception e) {
				// System.err.println(e);
			}
			return null;
		}
	};

	private static final String NAME = "External command provider";
	public Command() {
		super(NAME, 0.1, "KeyStore provider via executing external commands (config file has to be specified)");
	}
	public Command(String arg) {
		super(NAME, 0.1, "KeyStore provider via executing external commands");
		CommandKeyStore.Config attr = new CommandKeyStore.Config(arg);
		if (attr.containsKey("caching") && attr.get("caching").equals("true")) {
			putService(new CommandService(this, "KeyStore", attr.id(), CommandKeyStoreCaching.class.getName(), null, attr));
		} else {
			putService(new CommandService(this, "KeyStore", attr.id(), CommandKeyStore.class.getName(), null, attr));
		}
	}
	public Command(String name, double version, String info) {
		super(name, version, info);
	}
}
