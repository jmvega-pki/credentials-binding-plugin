package org.jenkinsci.plugins.credentialsbinding.refresh;

import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ExpandPerStepSpikeTest {
    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    @Test void expanderIsReevaluatedPerStep() throws Exception {
        WorkflowJob p = r.jenkins.createProject(WorkflowJob.class, "spike");
        // withSpikeToken is a tiny test step (next step) that wraps the body
        // with CountingSecretExpander via EnvironmentExpander.merge(...).
        p.setDefinition(new CpsFlowDefinition(
            "withSpikeToken {\n" +
            "  echo \"A=${env.SPIKE_TOKEN}\"\n" +
            "  echo \"B=${env.SPIKE_TOKEN}\"\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);
        // If expand() runs per step, the two reads differ.
        r.assertLogContains("A=tok-", b);
        r.assertLogContains("B=tok-", b);
        String log = b.getLog();
        assertPerStep(log);
    }

    private static void assertPerStep(String log) {
        java.util.regex.Matcher a = java.util.regex.Pattern.compile("A=tok-(\\d+)").matcher(log);
        java.util.regex.Matcher c = java.util.regex.Pattern.compile("B=tok-(\\d+)").matcher(log);
        if (!a.find() || !c.find()) throw new AssertionError("markers not found");
        int va = Integer.parseInt(a.group(1)), vb = Integer.parseInt(c.group(1));
        if (va == vb) throw new AssertionError(
            "expand() cached (A==B=" + va + "): per-step refresh NOT available; revisit design");
    }

    /** Test-only Pipeline step that wraps its body with a CountingSecretExpander. */
    public static class WithSpikeTokenStep extends org.jenkinsci.plugins.workflow.steps.Step {

        @org.kohsuke.stapler.DataBoundConstructor
        public WithSpikeTokenStep() {
        }

        @Override
        public org.jenkinsci.plugins.workflow.steps.StepExecution start(org.jenkinsci.plugins.workflow.steps.StepContext context) {
            return new Execution(context);
        }

        private static final class Execution extends org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution {
            private static final long serialVersionUID = 1L;

            Execution(org.jenkinsci.plugins.workflow.steps.StepContext context) {
                super(context);
            }

            @Override
            public boolean start() {
                run(this::doStart);
                return false;
            }

            private void doStart() throws Exception {
                getContext().newBodyInvoker()
                    .withContext(org.jenkinsci.plugins.workflow.steps.EnvironmentExpander.merge(
                        getContext().get(org.jenkinsci.plugins.workflow.steps.EnvironmentExpander.class),
                        new CountingSecretExpander()))
                    .withCallback(org.jenkinsci.plugins.workflow.steps.BodyExecutionCallback.wrap(getContext()))
                    .start();
            }
        }

        @org.jvnet.hudson.test.TestExtension("expanderIsReevaluatedPerStep")
        public static final class DescriptorImpl extends org.jenkinsci.plugins.workflow.steps.StepDescriptor {

            @Override
            public String getFunctionName() {
                return "withSpikeToken";
            }

            @edu.umd.cs.findbugs.annotations.NonNull
            @Override
            public String getDisplayName() {
                return "Spike test: wrap body with counting expander";
            }

            @Override
            public boolean takesImplicitBlockArgument() {
                return true;
            }

            @Override
            public java.util.Set<? extends Class<?>> getRequiredContext() {
                return java.util.Collections.emptySet();
            }
        }
    }
}
