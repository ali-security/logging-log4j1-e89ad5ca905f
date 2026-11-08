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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph, and the
 * number of nested elements a hashCode() of any of them may visit.
 *
 * Attack payloads are read on a separate daemon thread so that a vulnerable
 * stream fails the test after {@link #TIMEOUT_MILLIS} instead of hanging.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    private static final long TIMEOUT_MILLIS = 10000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Wraps the payload in a HashSet without hashing it: the payload is added
     * to a list that is already in the set, so its hashCode() is first computed
     * by HashSet.readObject() on the receiving side.
     */
    private Set hashedOnDeserialization(Object payload) {
        Set root = new HashSet();
        List holder = new ArrayList();
        root.add(holder);
        holder.add(payload);
        return root;
    }

    /**
     * The exact attack payload from the logback advisory: deeply nested
     * HashSets forming a DAG that causes O(2^N) hashCode() computation.
     */
    private Set deeplyNestedHashSet() {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    private LoggingEvent eventWithMdc(String message, Object mdcValue) {
        Map properties = new Hashtable();
        properties.put("key", mdcValue);
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        return new LoggingEvent(Logger.class.getName(), logger, System.currentTimeMillis(),
                Level.INFO, message, "main", null, null, null, properties);
    }

    /**
     * Reads one object from the stream on a daemon thread and returns the
     * Throwable the read failed with, or null when it succeeded. Fails when
     * the read is still running after {@link #TIMEOUT_MILLIS}.
     */
    private Throwable readWithTimeout(final HardenedObjectInputStream hois,
            final boolean adapted) throws InterruptedException {
        final Throwable[] failure = new Throwable[1];
        Thread reader = new Thread(new Runnable() {
            public void run() {
                try {
                    if (adapted) {
                        hois.readAdaptedObject();
                    } else {
                        hois.readObject();
                    }
                } catch (Throwable t) {
                    failure[0] = t;
                }
            }
        });
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT_MILLIS);
        assertFalse("Deserialization still running after " + TIMEOUT_MILLIS
                + " ms: CVE-2023-26464 denial of service", reader.isAlive());
        return failure[0];
    }

    private void assertRejected(HardenedObjectInputStream hois, boolean adapted)
            throws Exception {
        try {
            Throwable t = readWithTimeout(hois, adapted);
            assertNotNull("Payload should be rejected", t);
            assertTrue("Should be rejected with InvalidObjectException but got " + t,
                    t instanceof InvalidObjectException);
            assertTrue("Should mention collection limit",
                    t.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    private void assertRejected(Object payload) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(serialize(payload));
        assertRejected(new HardenedObjectInputStream(bis, new String[0]), false);
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        byte[] serialized = serialize(deeplyNestedHashSet());

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            Throwable t = readWithTimeout(hois, false);
            assertNotNull("Deeply nested HashSet should be rejected due to collection count limit", t);
            if (t instanceof InvalidObjectException) {
                // Our resolveObject-based collection count limit caught it (pre-JDK 9)
                assertTrue("Should mention collection limit",
                        t.getMessage().indexOf("collection") >= 0);
            } else {
                // On JDK 9+, the built-in ObjectInputFilter may reject it first
                // with "filter status: REJECTED". Either way, the attack is blocked.
                assertTrue("Unexpected failure: " + t, t instanceof java.io.InvalidClassException);
            }
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 with Hashtables, as carried by the LoggingEvent MDC:
     * a DAG of nested Hashtables whose hashCode() visits every path.
     */
    public void testDeeplyNestedHashtableRejected() throws Exception {
        Hashtable root = new Hashtable();
        Hashtable s1 = root;
        Hashtable s2 = new Hashtable();
        for (int i = 0; i < 100; i++) {
            Hashtable t1 = new Hashtable();
            Hashtable t2 = new Hashtable();
            t1.put("foo", "bar");
            s1.put("t1", t1);
            s1.put("t2", t2);
            s2.put("t1", t1);
            s2.put("t2", t2);
            s1 = t1;
            s2 = t2;
        }
        assertRejected(hashedOnDeserialization(root));
    }

    /**
     * Variant using few collections: lists that hold the same nested list many
     * times multiply the hashCode() cost at every level (64^8 element visits)
     * while staying far below the collection count limit.
     */
    public void testSharedNestedListsRejected() throws Exception {
        List list = new ArrayList();
        list.add("foo");
        for (int depth = 0; depth < 8; depth++) {
            List next = new ArrayList();
            for (int i = 0; i < 64; i++) {
                next.add(list);
            }
            list = next;
        }
        assertRejected(hashedOnDeserialization(list));
    }

    /**
     * Variant without nested collections: a chain of Map.Entry objects whose
     * key and value are the same entry doubles the hashCode() cost per link.
     */
    public void testNestedMapEntryChainRejected() throws Exception {
        Object entry = "foo";
        for (int i = 0; i < 64; i++) {
            entry = new AbstractMap.SimpleEntry(entry, entry);
        }
        assertRejected(hashedOnDeserialization(entry));
    }

    /**
     * Variant using virtual collections: Collections.nCopies() claims
     * Integer.MAX_VALUE elements while serializing to a few bytes, so a
     * hashCode() of two nested copies lists visits 2^62 elements.
     */
    public void testHugeVirtualCollectionRejected() throws Exception {
        List huge = Collections.nCopies(Integer.MAX_VALUE,
                Collections.nCopies(Integer.MAX_VALUE, "foo"));
        assertRejected(hashedOnDeserialization(huge));
    }

    /**
     * The SocketServer/Chainsaw attack path: the nested HashSets travel in
     * the MDC of a LoggingEvent read through readAdaptedObject().
     */
    public void testNestedCollectionsInLoggingEventRejected() throws Exception {
        byte[] serialized = serialize(eventWithMdc("attack", deeplyNestedHashSet()));
        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        assertRejected(new HardenedLoggingEventInputStream(bis), true);
    }

    /**
     * readAdaptedObject() gives each event its own collection budget, so a
     * stream carrying more MDC-bearing events than MAX_COLLECTION_COUNT is
     * still read completely.
     */
    public void testCollectionBudgetResetPerEvent() throws Exception {
        int eventCount = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 2;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < eventCount; i++) {
            oos.writeObject(eventWithMdc("message " + i, "alice"));
            oos.reset();
        }
        oos.close();

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(bis);
        try {
            for (int i = 0; i < eventCount; i++) {
                LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
                assertEquals("message " + i, event.getRenderedMessage());
                assertEquals("alice", event.getMDC("key"));
            }
        } finally {
            hleis.close();
        }
    }

    /**
     * End to end: a SocketNode receiving the attack payload must drop the
     * connection instead of spinning on hashCode() forever.
     */
    public void testSocketNodeClosesConnectionOnNestedCollections() throws Exception {
        byte[] serialized = serialize(eventWithMdc("attack", deeplyNestedHashSet()));

        Logger nodeLogger = Logger.getLogger(SocketNode.class);
        VectorAppender appender = new VectorAppender();
        nodeLogger.addAppender(appender);
        Level previousLevel = nodeLogger.getLevel();
        nodeLogger.setLevel(Level.INFO);

        ServerSocket serverSocket = new ServerSocket(0);
        Socket client = null;
        Socket accepted = null;
        try {
            client = new Socket("localhost", serverSocket.getLocalPort());
            accepted = serverSocket.accept();
            OutputStream out = client.getOutputStream();
            out.write(serialized);
            out.flush();

            SocketNode node = new SocketNode(accepted,
                    new Hierarchy(new RootLogger(Level.DEBUG)));
            Thread nodeThread = new Thread(node);
            nodeThread.setDaemon(true);
            nodeThread.start();
            nodeThread.join(TIMEOUT_MILLIS);
            assertFalse("SocketNode still deserializing after " + TIMEOUT_MILLIS
                    + " ms: CVE-2023-26464 denial of service", nodeThread.isAlive());
            assertTrue("SocketNode should close the connection", accepted.isClosed());

            boolean rejectionLogged = false;
            for (int i = 0; i < appender.getVector().size(); i++) {
                LoggingEvent logged = (LoggingEvent) appender.getVector().elementAt(i);
                if (logged.getRenderedMessage().indexOf("CVE-2023-26464") >= 0) {
                    rejectionLogged = true;
                }
            }
            assertTrue("SocketNode should log the rejected payload", rejectionLogged);
        } finally {
            nodeLogger.removeAppender(appender);
            nodeLogger.setLevel(previousLevel);
            if (client != null) {
                client.close();
            }
            if (accepted != null) {
                accepted.close();
            }
            serverSocket.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Nested collections that are not shared stay below the nested element
     * limit, however they are combined.
     */
    public void testNestedCollectionsWithinLimitAllowed() throws Exception {
        Set root = new HashSet();
        for (int i = 0; i < 16; i++) {
            List list = new ArrayList();
            for (int j = 0; j < 100; j++) {
                list.add("value " + i + "-" + j);
            }
            root.add(list);
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, new String[0]);

        Object result = hois.readObject();
        assertEquals(root, result);
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }
}
