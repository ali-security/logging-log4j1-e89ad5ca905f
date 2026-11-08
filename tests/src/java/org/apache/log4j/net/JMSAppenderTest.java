/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Vector;

import javax.jms.Topic;
import javax.jms.TopicConnectionFactory;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;

import junit.framework.TestCase;

import org.apache.log4j.Appender;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Regression tests for CVE-2021-4104: JMSAppender must not perform JNDI
 * lookups of attacker supplied TopicConnectionFactoryBindingName or
 * TopicBindingName values outside of the java: namespace.
 */
public class JMSAppenderTest extends TestCase {

  static final String TCF_JAVA_NAME = "java:comp/env/jms/TopicConnectionFactory";
  static final String TOPIC_JAVA_NAME = "java:comp/env/jms/Topic";
  static final String ATTACKER_PROVIDER_URL = "ldap://127.0.0.1:1389/";
  static final String ATTACKER_LDAP_NAME = "ldap://127.0.0.1:1389/Exploit";
  static final String ATTACKER_RMI_NAME = "rmi://127.0.0.1:1099/Exploit";
  static final String ATTACKER_PLAIN_NAME = "Exploit";

  /** Names that reached Context.lookup of the recording JNDI context. */
  static final Vector lookedUpNames = new Vector();

  public JMSAppenderTest(final String testName) {
    super(testName);
  }

  protected void setUp() {
    lookedUpNames.clear();
  }

  protected void tearDown() {
    LogManager.resetConfiguration();
    lookedUpNames.clear();
  }

  public void testLookupRejectsLdapName() {
    assertLookupRejected(ATTACKER_LDAP_NAME);
  }

  public void testLookupRejectsRmiName() {
    assertLookupRejected(ATTACKER_RMI_NAME);
  }

  public void testLookupRejectsNameOutsideJavaNamespace() {
    assertLookupRejected(ATTACKER_PLAIN_NAME);
  }

  public void testLookupAllowsJavaNamespace() throws NamingException {
    JMSAppender appender = new JMSAppender();
    Object result = appender.lookup(createRecordingContext(), TCF_JAVA_NAME);
    assertTrue(result instanceof TopicConnectionFactory);
    assertEquals(1, lookedUpNames.size());
    assertEquals(TCF_JAVA_NAME, lookedUpNames.elementAt(0));
  }

  /**
   * TopicConnectionFactoryBindingName pointing at an attacker controlled
   * JNDI provider must not be looked up.
   */
  public void testActivateOptionsRejectsTopicConnectionFactoryBindingName() {
    JMSAppender appender = createAttackerConfiguredAppender();
    RecordingErrorHandler errorHandler = new RecordingErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setTopicConnectionFactoryBindingName(ATTACKER_PLAIN_NAME);
    appender.setTopicBindingName(TOPIC_JAVA_NAME);

    appender.activateOptions();

    assertEquals("no JNDI lookup expected", 0, lookedUpNames.size());
    assertRestrictionReported(errorHandler, ATTACKER_PLAIN_NAME);
    assertNull(appender.getTopicConnection());
    assertNull(appender.getTopicPublisher());
    appender.close();
  }

  /**
   * TopicBindingName pointing at an attacker controlled JNDI provider must
   * not be looked up, even when the connection factory name is valid.
   */
  public void testActivateOptionsRejectsTopicBindingName() {
    JMSAppender appender = createAttackerConfiguredAppender();
    RecordingErrorHandler errorHandler = new RecordingErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setTopicConnectionFactoryBindingName(TCF_JAVA_NAME);
    appender.setTopicBindingName(ATTACKER_PLAIN_NAME);

    appender.activateOptions();

    assertEquals(1, lookedUpNames.size());
    assertEquals(TCF_JAVA_NAME, lookedUpNames.elementAt(0));
    assertRestrictionReported(errorHandler, ATTACKER_PLAIN_NAME);
    assertNull(appender.getTopicPublisher());
    appender.close();
  }

  /**
   * End-to-end attack through a log4j configuration file: neither binding
   * name may reach the JNDI provider chosen by the configuration.
   */
  public void testPropertyConfigurationDoesNotLookupAttackerNames() {
    Properties props = new Properties();
    props.setProperty("log4j.logger.org.apache.log4j.net.JMSAppenderTest.attack", "DEBUG, JMS");
    props.setProperty("log4j.additivity.org.apache.log4j.net.JMSAppenderTest.attack", "false");
    props.setProperty("log4j.appender.JMS", JMSAppender.class.getName());
    props.setProperty("log4j.appender.JMS.InitialContextFactoryName",
                      RecordingContextFactory.class.getName());
    props.setProperty("log4j.appender.JMS.ProviderURL", ATTACKER_PROVIDER_URL);
    props.setProperty("log4j.appender.JMS.TopicConnectionFactoryBindingName",
                      ATTACKER_PLAIN_NAME);
    props.setProperty("log4j.appender.JMS.TopicBindingName", ATTACKER_PLAIN_NAME);

    PropertyConfigurator.configure(props);

    Logger logger = Logger.getLogger("org.apache.log4j.net.JMSAppenderTest.attack");
    Appender appender = logger.getAppender("JMS");
    assertTrue(appender instanceof JMSAppender);
    assertEquals(ATTACKER_PLAIN_NAME,
                 ((JMSAppender) appender).getTopicConnectionFactoryBindingName());
    assertEquals("no JNDI lookup expected", 0, lookedUpNames.size());
  }

  private void assertLookupRejected(String name) {
    JMSAppender appender = new JMSAppender();
    try {
      appender.lookup(createRecordingContext(), name);
      fail("lookup of [" + name + "] should have been rejected");
    } catch (NamingException e) {
      assertTrue(e.getMessage(), e.getMessage().startsWith(JNDIUtil.RESTRICTION_MSG));
    }
    assertEquals("no JNDI lookup expected", 0, lookedUpNames.size());
  }

  private static void assertRestrictionReported(RecordingErrorHandler errorHandler,
                                                String name) {
    assertNotNull("error handler not invoked", errorHandler.exception);
    assertTrue(errorHandler.exception instanceof NamingException);
    assertEquals(JNDIUtil.RESTRICTION_MSG + name, errorHandler.exception.getMessage());
  }

  private static JMSAppender createAttackerConfiguredAppender() {
    JMSAppender appender = new JMSAppender();
    appender.setName("JMS");
    appender.setInitialContextFactoryName(RecordingContextFactory.class.getName());
    appender.setProviderURL(ATTACKER_PROVIDER_URL);
    return appender;
  }

  static Context createRecordingContext() {
    return (Context) Proxy.newProxyInstance(JMSAppenderTest.class.getClassLoader(),
        new Class[] { Context.class },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) {
            if ("lookup".equals(method.getName())) {
              String name = String.valueOf(args[0]);
              lookedUpNames.addElement(name);
              if (TCF_JAVA_NAME.equals(name)) {
                return createStub(TopicConnectionFactory.class);
              }
              return createStub(Topic.class);
            }
            return handleDefault(proxy, method, args, Context.class);
          }
        });
  }

  /**
   * Creates a dynamic proxy for a JMS interface in which every method
   * returning an interface returns a stub of that interface and every other
   * method does nothing.
   */
  static Object createStub(final Class type) {
    return Proxy.newProxyInstance(JMSAppenderTest.class.getClassLoader(),
        new Class[] { type },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) {
            return handleDefault(proxy, method, args, type);
          }
        });
  }

  static Object handleDefault(Object proxy, Method method, Object[] args, Class type) {
    String name = method.getName();
    if ("equals".equals(name) && args != null && args.length == 1) {
      return (proxy == args[0]) ? Boolean.TRUE : Boolean.FALSE;
    }
    if ("hashCode".equals(name) && (args == null || args.length == 0)) {
      return new Integer(System.identityHashCode(proxy));
    }
    if ("toString".equals(name) && (args == null || args.length == 0)) {
      return "stub " + type.getName();
    }
    Class returnType = method.getReturnType();
    if (returnType.isInterface()) {
      return createStub(returnType);
    }
    return null;
  }

  /**
   * JNDI provider standing in for an attacker controlled naming service.
   */
  public static class RecordingContextFactory implements InitialContextFactory {
    public Context getInitialContext(Hashtable environment) {
      return createRecordingContext();
    }
  }

  static class RecordingErrorHandler implements ErrorHandler {
    String message;
    Exception exception;

    public void setLogger(Logger logger) {
    }

    public void error(String message, Exception e, int errorCode) {
      record(message, e);
    }

    public void error(String message) {
      record(message, null);
    }

    public void error(String message, Exception e, int errorCode, LoggingEvent event) {
      record(message, e);
    }

    public void setAppender(Appender appender) {
    }

    public void setBackupAppender(Appender appender) {
    }

    public void activateOptions() {
    }

    private void record(String message, Exception e) {
      if (this.message == null) {
        this.message = message;
        this.exception = e;
      }
    }
  }
}
