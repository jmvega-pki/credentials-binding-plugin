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

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.util.Secret;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test for the gating patch in {@code BindingStep.doStart()}.
 *
 * <p>Behavioral pipeline test: it runs a real {@code withCredentials} block over a real
 * {@link StringCredentials} in the system store. Because the union-masking filter (correctly)
 * hides token values from the console, the resolved values cannot be read back from the build
 * log; instead the {@link TestRefreshableCredential} records every value it hands out server-side
 * so the test can observe whether the credential was re-resolved (refresh) or cached (stock).
 */
@WithJenkins
class BindingStepGateTest {

    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    @Test
    void configuredIdRefreshesBetweenSteps() throws Exception {
        TestRefreshableCredential.register(r, "cred-1");
        RefreshBindingConfiguration.get().setCredentialIds(List.of("cred-1"));

        WorkflowJob p = r.jenkins.createProject(WorkflowJob.class, "gated");
        p.setDefinition(new CpsFlowDefinition(
            "withCredentials([string(credentialsId: 'cred-1', variable: 'TOKEN')]) {\n" +
            "  echo \"A=${env.TOKEN}\"\n" +
            "  echo \"B=${env.TOKEN}\"\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);

        List<String> resolved = TestRefreshableCredential.resolutions("cred-1");
        // Refreshing => the binding is re-resolved on every step, so at least two distinct
        // tokens are produced across the two echo steps.
        assertTrue(distinct(resolved) >= 2,
            "refreshing should re-resolve per step (>=2 distinct tokens), got: " + resolved);
        // The two refreshed values differ (proved via the recorded resolutions, since the log is masked).
        DifferAssert.assertDifferentMarkers("A=" + resolved.get(0) + "\nB=" + resolved.get(1), "A=", "B=");
        // ...and neither value leaks into the console (union-masked).
        for (String v : resolved) {
            r.assertLogNotContains(v, b);
        }
    }

    @Test
    void nonConfiguredIdKeepsStockCaching() throws Exception {
        TestRefreshableCredential.register(r, "cred-2");
        RefreshBindingConfiguration.get().setCredentialIds(Collections.emptyList()); // empty selection
        WorkflowJob p = r.jenkins.createProject(WorkflowJob.class, "stock");
        p.setDefinition(new CpsFlowDefinition(
            "withCredentials([string(credentialsId: 'cred-2', variable: 'TOKEN')]) {\n" +
            "  echo \"A=${env.TOKEN}\"\n" +
            "  echo \"B=${env.TOKEN}\"\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);

        List<String> resolved = TestRefreshableCredential.resolutions("cred-2");
        // Stock caching => the binding is resolved once at step start; only a single distinct
        // token is ever produced regardless of how many steps read it.
        assertEquals(1, distinct(resolved),
            "stock path should cache a single value, got: " + resolved);
        // Both masked reads render identically in the log.
        DifferAssert.assertSameMarkers(b.getLog(), "A=", "B=");
    }

    @Test
    void refreshingCredentialSerializesWithLiveLauncher() throws Exception {
        // Exercise a live Launcher (node{}), which CPS persists at step boundaries. If
        // RefreshingOverrider persisted its Launcher this would throw NotSerializableException; with
        // transient context it serializes cleanly and still refreshes.
        TestRefreshableCredential.register(r, "cred-3");
        RefreshBindingConfiguration.get().setCredentialIds(List.of("cred-3"));

        WorkflowJob p = r.jenkins.createProject(WorkflowJob.class, "node-live");
        p.setDefinition(new CpsFlowDefinition(
            "node {\n" +
            "  withCredentials([string(credentialsId: 'cred-3', variable: 'TOKEN')]) {\n" +
            "    isUnix()\n" +
            "    echo \"A=${env.TOKEN}\"\n" +
            "    echo \"B=${env.TOKEN}\"\n" +
            "  }\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);

        List<String> resolved = TestRefreshableCredential.resolutions("cred-3");
        assertTrue(distinct(resolved) >= 2,
            "refreshing should re-resolve per step even with a live launcher, got: " + resolved);
        for (String v : resolved) {
            r.assertLogNotContains(v, b);
        }
    }

    @Test
    void refreshingTokenIsMaskedInThrownExceptionMessage() throws Exception {
        // A refreshing token embedded in a thrown exception message must be masked on the failure
        // surface (ErrorAction / catch(e).getMessage()), not just the console. We catch the error and
        // echo its message OUTSIDE the withCredentials block, where the console filter no longer
        // applies -- so only the FailureHandler masking can prevent the leak.
        TestRefreshableCredential.register(r, "cred-4");
        RefreshBindingConfiguration.get().setCredentialIds(List.of("cred-4"));

        WorkflowJob p = r.jenkins.createProject(WorkflowJob.class, "err-mask");
        p.setDefinition(new CpsFlowDefinition(
            "try {\n" +
            "  withCredentials([string(credentialsId: 'cred-4', variable: 'TOKEN')]) {\n" +
            "    error(\"boom token=${env.TOKEN}\")\n" +
            "  }\n" +
            "} catch (e) {\n" +
            "  echo \"CAUGHT=${e.getMessage()}\"\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);

        List<String> resolved = TestRefreshableCredential.resolutions("cred-4");
        assertTrue(!resolved.isEmpty(), "token should have been resolved");
        // The rotated token must NOT appear anywhere in the log (the caught message is echoed outside
        // the masked block, so this only passes if the FailureHandler masked the exception).
        for (String v : resolved) {
            r.assertLogNotContains(v, b);
        }
        r.assertLogContains("CAUGHT=boom token=****", b);
    }

    private static int distinct(List<String> values) {
        return new LinkedHashSet<>(values).size();
    }

    /**
     * A {@link StringCredentials} whose secret value increments every time it is resolved,
     * simulating a credential that is rotated on each read. Every value handed out is recorded
     * in a static, per-id sink so tests can inspect the resolution sequence server-side (the log
     * is masked). Keying the sink and counter statically by id makes it robust to per-run cloning
     * (snapshot / {@code forRun}) done by the credentials provider.
     */
    static final class TestRefreshableCredential extends BaseStandardCredentials implements StringCredentials {

        private static final Map<String, List<String>> RESOLUTIONS = new ConcurrentHashMap<>();

        TestRefreshableCredential(CredentialsScope scope, String id, String description) {
            super(scope, id, description);
        }

        @Override
        public Secret getSecret() {
            List<String> list = RESOLUTIONS.computeIfAbsent(getId(),
                k -> Collections.synchronizedList(new ArrayList<>()));
            String value;
            synchronized (list) {
                value = "tok-" + getId() + "-" + (list.size() + 1);
                list.add(value);
            }
            return Secret.fromString(value);
        }

        static void register(JenkinsRule r, String id) throws Exception {
            RESOLUTIONS.remove(id);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next()
                .addCredentials(Domain.global(),
                    new TestRefreshableCredential(CredentialsScope.GLOBAL, id, "test refreshable credential " + id));
        }

        static List<String> resolutions(String id) {
            List<String> list = RESOLUTIONS.get(id);
            if (list == null) {
                return Collections.emptyList();
            }
            synchronized (list) {
                return new ArrayList<>(list);
            }
        }
    }

    /**
     * Compares the value that follows one {@code X=} marker with the value that follows another,
     * inside a text blob (a build log, or a synthetic two-line blob of recorded resolutions).
     */
    static final class DifferAssert {

        private DifferAssert() {
        }

        static String marker(String text, String marker) {
            // Anchor to the start of a line so we match the bare "echo" output line
            // (e.g. "A=****") rather than an incidental occurrence elsewhere in the log.
            Matcher m = Pattern.compile("(?m)^" + Pattern.quote(marker) + "(\\S*)$").matcher(text);
            assertTrue(m.find(), "marker not found: " + marker);
            return m.group(1);
        }

        static void assertDifferentMarkers(String text, String a, String b) {
            assertNotEquals(marker(text, a), marker(text, b),
                "expected markers '" + a + "' and '" + b + "' to differ");
        }

        static void assertSameMarkers(String text, String a, String b) {
            assertEquals(marker(text, a), marker(text, b),
                "expected markers '" + a + "' and '" + b + "' to match");
        }
    }
}
