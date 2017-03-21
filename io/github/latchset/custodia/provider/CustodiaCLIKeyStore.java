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

import java.util.Hashtable;

public class CustodiaCLIKeyStore extends CommandKeyStoreCaching {

	static final Hashtable<String, String> DEFAULT_CONFIG = new Hashtable<String, String>() {{
		put("command", "custodia-cli");
		put("command-aliases", "${command} ls ${container}");
		put("command-get", "${command} get ${container/}${alias}");
		put("command-set", "${command} set ${container/}${alias} ${value}");
		put("command-del", "${command} del ${container/}${alias}");
	}};

	static class Config extends CommandKeyStoreCaching.Config {
		Config(Hashtable<String, String> orig) {
			super(orig);
		}
		Config(String arg) {
			super(arg);
			for (String k : DEFAULT_CONFIG.keySet()) {
				if (!containsKey(k)) {
					put(k, DEFAULT_CONFIG.get(k));
				}
			}
		}
	};

	public CustodiaCLIKeyStore() {
		super(new Config(DEFAULT_CONFIG));
	}

	public CustodiaCLIKeyStore(CommandKeyStore.Config attr) {
		super(attr);
	}

};
