/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.gssapi;

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Proivder is used to register the implementation of gssapi mechanism into the system
 */
public final class Provider extends java.security.Provider {
    private static final long serialVersionUID = 3787378212107821987L;
    private static final String INFO = "Kerby GssApi Provider";
    private static final String MECHANISM_GSSAPI = "GssApiMechanism.1.2.840.113554.1.2.2";
    private static final String MECHANISM_GSSAPI_CLASS = "org.apache.kerby.kerberos.kerb.gssapi.KerbyMechFactory";

    public Provider() {
        super("KerbyGssApi", 0.01d, INFO);

        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {

                put(MECHANISM_GSSAPI, MECHANISM_GSSAPI_CLASS);

                return null;
            }
        });
    }
}