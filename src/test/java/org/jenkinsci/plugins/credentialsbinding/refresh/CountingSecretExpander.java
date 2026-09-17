package org.jenkinsci.plugins.credentialsbinding.refresh;

import hudson.EnvVars;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;

/** Test-only: yields a different value each time expand() is called. */
public class CountingSecretExpander extends EnvironmentExpander {
    private final AtomicInteger n = new AtomicInteger();
    @Override public void expand(EnvVars env) throws IOException, InterruptedException {
        env.override("SPIKE_TOKEN", "tok-" + n.incrementAndGet());
    }
}
