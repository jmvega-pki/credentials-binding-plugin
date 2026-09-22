/*
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.credentialsbinding.refresh;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link RefreshingOverrider}.
 */
@WithJenkins
class RefreshingOverriderTest {

    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    @Test
    void expandReresolvesEachCall() throws Exception {
        FakeCountingBinding binding = new FakeCountingBinding("cred-1", "TOKEN");
        RefreshingFilter filter = new RefreshingFilter();
        RefreshingOverrider o = new RefreshingOverrider(
            Collections.singletonList(binding),
            null, null, null, null, filter);

        EnvVars e1 = new EnvVars();
        o.expand(e1);
        EnvVars e2 = new EnvVars();
        o.expand(e2);

        assertEquals("tok-1", e1.get("TOKEN"));
        assertEquals("tok-2", e2.get("TOKEN")); // refreshed, not cached
        assertTrue(o.getSensitiveVariables().contains("TOKEN"));
        assertTrue(filter.knownSecrets().contains("tok-1"));
        assertTrue(filter.knownSecrets().contains("tok-2")); // union kept for masking
    }

    /**
     * Regression test for the NotSerializableException that broke CPS program persistence
     * (e.g. Release-Apps-SDK #785): the non-Serializable {@link MultiBinding} objects must not be
     * serialized with the overrider. {@code bindings} is transient, so a round-trip succeeds, and
     * after "restart" (deserialization) expand() falls back to the last-known values.
     */
    @Test
    void survivesSerializationRoundTrip() throws Exception {
        FakeCountingBinding binding = new FakeCountingBinding("cred-1", "TOKEN");
        RefreshingFilter filter = new RefreshingFilter();
        RefreshingOverrider o = new RefreshingOverrider(
            Collections.singletonList(binding),
            null, null, null, null, filter);

        // Resolve once so the last-known values are populated before persistence.
        o.expand(new EnvVars());

        // CPS persists the program graph mid-run; the non-Serializable binding must not travel with it.
        byte[] bytes;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            assertDoesNotThrow(() -> oos.writeObject(o),
                "RefreshingOverrider must serialize without dragging in the non-Serializable bindings");
            oos.flush();
            bytes = bos.toByteArray();
        }

        // After a controller restart the deserialized copy has no live context; expand() must fall
        // back to the persisted last-known values instead of throwing.
        RefreshingOverrider restored;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            restored = (RefreshingOverrider) ois.readObject();
        }
        EnvVars afterRestart = new EnvVars();
        restored.expand(afterRestart);
        assertEquals("tok-1", afterRestart.get("TOKEN"), "should write last-known value post-restart");
        assertTrue(restored.getSensitiveVariables().contains("TOKEN"));
    }

    /**
     * Test helper that simulates a refreshable credential binding.
     * Returns an incrementing secret value on each bind() call.
     */
    static class FakeCountingBinding extends MultiBinding<StandardCredentials> {
        private int counter = 0;
        private final String variableName;

        FakeCountingBinding(String credentialsId, String variableName) {
            super(credentialsId);
            this.variableName = variableName;
        }

        @Override
        protected Class<StandardCredentials> type() {
            return StandardCredentials.class;
        }

        @Override
        public MultiEnvironment bind(@NonNull Run<?, ?> build,
                                     @Nullable FilePath workspace,
                                     @Nullable Launcher launcher,
                                     @NonNull TaskListener listener) {
            counter++;
            Map<String, String> secretValues = new LinkedHashMap<>();
            secretValues.put(variableName, "tok-" + counter);
            return new MultiEnvironment(secretValues);
        }

        @Override
        public Set<String> variables(@NonNull Run<?, ?> build) {
            return Collections.singleton(variableName);
        }
    }
}
