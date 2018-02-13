/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import org.apache.kerby.has.common.HasConfig;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.glassfish.jersey.SslConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.ws.rs.core.MultivaluedMap;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * HAS client API for applications to interact with HAS server
 */
public class HasInitClient {

    public static final Logger LOG = LoggerFactory.getLogger(HasInitClient.class);

    private HasConfig hasConfig;
    private File confDir;

    public HasInitClient(HasConfig hasConfig, File confDir) {
        this.hasConfig = hasConfig;
        this.confDir = confDir;
    }

    public File getConfDir() {
        return confDir;
    }

    private WebResource getWebResource(String restName) {
        Client client;
        String server = null;
        if (hasConfig.getHttpsPort() != null && hasConfig.getHttpsHost() != null) {
            server = "https://" + hasConfig.getHttpsHost() + ":" + hasConfig.getHttpsPort()
                    + "/has/v1/" + restName;
            LOG.info("Admin request url: " + server);
            HasConfig conf = new HasConfig();
            try {
                conf.addIniConfig(new File(hasConfig.getSslClientConf()));
            } catch (IOException e) {
                throw new RuntimeException("Errors occurred when adding ssl conf. "
                    + e.getMessage());
            }
            SslConfigurator sslConfigurator = SslConfigurator.newInstance()
                    .trustStoreFile(conf.getString("ssl.client.truststore.location"))
                    .trustStorePassword(conf.getString("ssl.client.truststore.password"));
            sslConfigurator.securityProtocol("SSL");
            SSLContext sslContext = sslConfigurator.createSSLContext();
            ClientConfig clientConfig = new DefaultClientConfig();
            clientConfig.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES,
                    new HTTPSProperties(new HostnameVerifier() {
                        @Override
                        public boolean verify(String s, SSLSession sslSession) {
                            return false;
                        }
                    }, sslContext));
            client = Client.create(clientConfig);
        } else {
            client = Client.create();
        }
        if (server == null) {
            throw new RuntimeException("Please set the https address and port.");
        }
        return client.resource(server);
    }

    public void startKdc() {
        WebResource webResource = getWebResource("init/kdcstart");
        ClientResponse response = webResource.get(ClientResponse.class);
        try {
            JSONObject result = new JSONObject(response.getEntity(String.class));
            if (result.getString("result").equals("success")) {
                System.out.println(result.getString("msg"));
            } else {
                System.err.println(result.getString("msg"));
            }
        } catch (JSONException e) {
            System.err.println(e.getMessage());
        }
    }

    public InputStream initKdc() {
        WebResource webResource = getWebResource("init/kdcinit");
        ClientResponse response = webResource.get(ClientResponse.class);
        if (response.getStatus() == 200) {
            return response.getEntityInputStream();
        }
        return null;
    }
}
