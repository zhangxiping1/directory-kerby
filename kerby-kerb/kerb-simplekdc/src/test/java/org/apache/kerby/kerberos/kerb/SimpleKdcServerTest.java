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
package org.apache.kerby.kerberos.kerb;

import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.util.NetworkUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Properties;

import static org.apache.kerby.kerberos.kerb.MiniKdc.MAX_TICKET_LIFETIME;

public class SimpleKdcServerTest {
    private String serverHost = "localhost";
    private int serverPort = -1;

    private KdcServer kdcServer;

    @Before
    public void setUp() throws Exception {
        kdcServer = new SimpleKdcServer();
        kdcServer.setKdcHost(serverHost);
        kdcServer.setAllowUdp(false);
        kdcServer.setAllowTcp(true);
        serverPort = NetworkUtil.getServerPort();
        kdcServer.setKdcTcpPort(serverPort);
        kdcServer.init();
        kdcServer.start();
    }

    @Test
    public void testKdc() throws IOException, InterruptedException {
        SocketChannel socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.connect(sa);


        String badKrbMessage = "Hello World!";
        ByteBuffer writeBuffer = ByteBuffer.allocate(4 + badKrbMessage.getBytes().length);
        writeBuffer.putInt(badKrbMessage.getBytes().length);
        writeBuffer.put(badKrbMessage.getBytes());
        writeBuffer.flip();

        socketChannel.write(writeBuffer);
    }


    @Test
    public void testKDC() throws Exception {
        //setLogLevel();
        System.setProperty("hadoop.log.file","KDC.log");
        //先清理classpath配置文件
        //clearClassPath();
        Configuration conf = new Configuration();
        UserGroupInformation.setConfiguration(conf);
        Properties kConf = MiniKdc.createConf();
        kConf.setProperty("debug","true");
        kConf.setProperty("kdc.port","2222");
        kConf.setProperty("org.name","EXAMPLE");
        kConf.setProperty("org.domain","COM");
        kConf.setProperty("transport","TCP");
        kConf.setProperty(MAX_TICKET_LIFETIME, "86400000");
        MiniKdc kdc = new MiniKdc(kConf, new File(new File("D:\\project\\myproject\\directory-kerby\\kerby-kerb\\kerb-server\\target"), "kdc"));
        kdc.start();

        conf.set("hadoop.security.authorization","true");
        conf.set("hadoop.security.authentication","kerberos");
        //conf.set("ipc.client.fallback-to-simple-auth-allowed","true");

        conf.set("hadoop.security.auth_to_local","RULE:[2:$1@$0](.*@EXAMPLE.COM)s/.*/zhangxiping/\n"+"DEFAULT");
        // NN 可能依赖环境变量里面的配置
        conf.set("dfs.journalnode.kerberos.principal","zhangxiping/127.0.0.1@EXAMPLE.COM");
        conf.set("dfs.journalnode.keytab.file","/Users/temp/zhangxiping.keytab");
        conf.set("dfs.journalnode.kerberos.principal","zhangxiping/127.0.0.1@EXAMPLE.COM");
        conf.set("dfs.journalnode.kerberos.internal.spnego.principal","HTTP/127.0.0.1@EXAMPLE.COM");
        conf.set("dfs.qjournal.queued-edits.limit.mb","1");

        UserGroupInformation.setShouldRenewImmediatelyForTests(true);
        String [] principals = new String[]{"jh/127.0.0.1","rm/127.0.0.1","nm/127.0.0.1","jn/127.0.0.1","nn/127.0.0.1","dn/127.0.0.1","hdfs/127.0.0.1","zhangxiping/127.0.0.1","HTTP/127.0.0.1"};
        File keytab = new File("/Users/temp/zhangxiping.keytab");
        System.out.println("============="+keytab.getAbsolutePath());
        // window 默认会加载  C://windows/krb5.ini
        FileUtils.copyFile(new File( "D:\\project\\neproject\\3.3.0\\ne-hadoop\\hadoop-mapreduce-project\\hadoop-mapreduce-client\\hadoop-mapreduce-client-jobclient/target/test-classes/krb5.conf"), new File("C:\\windows\\krb5.ini"));
        FileUtils.copyFile(new File( "D:\\project\\neproject\\3.3.0\\ne-hadoop\\hadoop-mapreduce-project\\hadoop-mapreduce-client\\hadoop-mapreduce-client-jobclient/target/test-classes/keystore.jks"), new File("/Users/temp/keystore.jks"));
        FileUtils.copyFile(new File( "D:\\project\\neproject\\3.3.0\\ne-hadoop\\hadoop-mapreduce-project\\hadoop-mapreduce-client\\hadoop-mapreduce-client-jobclient/target/test-classes/truststore.jks"), new File("/Users/temp/truststore.jks"));

        kdc.createPrincipal(keytab, principals);
        FileUtils.copyFile(new File("/Users/temp/zhangxiping.keytab"), new File("/hadoop-2.9.2-1.1.1.5/etc/hadoop/krb5.keytab"));
        conf.set("hadoop.http.authentication.simple.anonymous.allowed","true");
        conf.set("hadoop.http.filter.initializers","org.apache.hadoop.security.AuthenticationFilterInitializer");
        conf.set("hadoop.http.authentication.signature.secret.file","/Users/temp/hadoop-http-auth-signature-secret");

        conf.writeXml(new FileOutputStream(new File( "D:\\project\\neproject\\3.3.0\\ne-hadoop\\hadoop-mapreduce-project\\hadoop-mapreduce-client\\hadoop-mapreduce-client-jobclient/target/test-classes/core-site.xml")));
        conf.writeXml(new FileOutputStream(new File( "D:\\project\\neproject\\3.3.0\\ne-hadoop\\hadoop-mapreduce-project\\hadoop-mapreduce-client\\hadoop-mapreduce-client-jobclient/target/test-classes/hdfs-site.xml")));
        System.out.println("----------write success!!");
        System.in.read();
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}
