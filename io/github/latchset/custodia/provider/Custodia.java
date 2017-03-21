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

public final class Custodia extends Command {

	private static final long serialVersionUID = 2550192477529348189L;

	private static final String ID = "custodia-cli";
	private static final String NAME = "Custodia provider";

	public Custodia() {
		super(NAME, 0.1, "Custodia CLI provier");
		put("KeyStore." + ID, CustodiaCLIKeyStore.class.getName());
	}
	public Custodia(String arg) {
		super(NAME, 0.1, "Custodia CLI provier");
		CustodiaCLIKeyStore.Config attr = new CustodiaCLIKeyStore.Config(arg);
		putService(new Command.CommandService(this, "KeyStore", attr.id(ID), CustodiaCLIKeyStore.class.getName(), null, attr));
	}
}
