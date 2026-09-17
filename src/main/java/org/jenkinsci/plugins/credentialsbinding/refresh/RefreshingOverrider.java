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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Re-resolves selected bindings on each expand() so tokens stay fresh.
 * Instead of caching the bound secret, this EnvironmentExpander calls bind() on every expand() call
 * (each Pipeline step) to get fresh values, and feeds each new value to the RefreshingFilter for masking.
 *
 * <p>This object is persisted by CPS in two places (the body's EnvironmentExpander context
 * and {@code BindingStep.Callback2}). The build context ({@code run}/{@code workspace}/{@code launcher}/
 * {@code listener}) is not durably serializable ({@link Launcher} in particular), so those fields are
 * {@code transient}. CPS keeps the live in-memory object across step boundaries within a run, so the
 * transient fields survive normal operation and per-step refreshing keeps working; they are only null
 * after an actual controller restart mid-step. To degrade gracefully in that window, the last
 * successfully-resolved values are kept in serializable fields (secrets as {@link Secret}, mirroring the
 * stock Overrider) and written when the live context is unavailable, instead of throwing.
 */
@SuppressFBWarnings(
        value = {"SE_BAD_FIELD", "SE_TRANSIENT_FIELD_NOT_RESTORED"},
        justification = "'bindings' holds Describable bindings that are serializable at "
                + "runtime (their declared type is not marked Serializable, so SpotBugs cannot prove it); "
                + "the transient build-context fields (run/workspace/launcher/listener/liveContext) are "
                + "intentionally not restored on deserialization -- after a controller restart expand() "
                + "falls back to the persisted last-known values instead of the (now null) live context.")
public class RefreshingOverrider extends EnvironmentExpander {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(RefreshingOverrider.class.getName());

    private final List<MultiBinding<?>> bindings;
    private final RefreshingFilter filter;
    private final Set<String> variableNames;
    private final List<MultiBinding.Unbinder> unbinders = new ArrayList<>();

    // Last successfully-resolved values, persisted so expand() can still populate the environment
    // (and re-arm masking) after a controller restart drops the transient context below.
    private final Map<String, Secret> lastSecretValues = Collections.synchronizedMap(new LinkedHashMap<>());
    private final Map<String, String> lastPublicValues = Collections.synchronizedMap(new LinkedHashMap<>());

    // Build context: not durably serializable, so transient. Retained in-memory across step boundaries
    // within a run; null only after an actual controller restart mid-step.
    private transient Run<?, ?> run;
    private transient FilePath workspace;
    private transient Launcher launcher;
    private transient TaskListener listener;
    // True on a freshly-constructed instance; false after deserialization (transient default), which
    // is how we detect "context lost across a restart" without conflating it with a legitimately null
    // context passed in unit tests.
    private transient boolean liveContext;

    public RefreshingOverrider(List<MultiBinding<?>> bindings, Run<?, ?> run,
                               FilePath workspace, Launcher launcher,
                               TaskListener listener, RefreshingFilter filter)
            throws IOException, InterruptedException {
        this.bindings = bindings;
        this.run = run;
        this.workspace = workspace;
        this.launcher = launcher;
        this.listener = listener;
        this.filter = filter;
        this.liveContext = true;
        this.variableNames = new LinkedHashSet<>();
        for (MultiBinding<?> b : bindings) {
            variableNames.addAll(b.variables(run));
        }
    }

    @Override
    public void expand(@NonNull EnvVars env) throws IOException, InterruptedException {
        if (!liveContext) {
            // Context was dropped across a controller restart (transient fields). Degrade gracefully
            // by writing the last successfully-resolved values instead of crashing.
            LOGGER.log(Level.FINE, "RefreshingOverrider live context unavailable (post-restart); "
                    + "writing last-known values for {0}", variableNames);
            writeLastKnown(env);
            return;
        }
        for (MultiBinding<?> b : bindings) {
            MultiBinding.MultiEnvironment me = b.bind(run, workspace, launcher, listener);
            synchronized (unbinders) {
                unbinders.add(me.getUnbinder());
            }
            // Write secret values to env, add to filter, and remember them for post-restart fallback.
            for (Map.Entry<String, String> e : me.getSecretValues().entrySet()) {
                env.override(e.getKey(), e.getValue());
                filter.add(e.getValue());
                lastSecretValues.put(e.getKey(), Secret.fromString(e.getValue()));
            }
            // Write public values to env (and remember them too).
            for (Map.Entry<String, String> e : me.getPublicValues().entrySet()) {
                env.override(e.getKey(), e.getValue());
                lastPublicValues.put(e.getKey(), e.getValue());
            }
        }
    }

    private void writeLastKnown(@NonNull EnvVars env) {
        synchronized (lastSecretValues) {
            for (Map.Entry<String, Secret> e : lastSecretValues.entrySet()) {
                String value = e.getValue().getPlainText();
                env.override(e.getKey(), value);
                filter.add(value);
            }
        }
        synchronized (lastPublicValues) {
            for (Map.Entry<String, String> e : lastPublicValues.entrySet()) {
                env.override(e.getKey(), e.getValue());
            }
        }
    }

    @Override
    @NonNull
    public Set<String> getSensitiveVariables() {
        return variableNames;
    }

    /**
     * Run every unbinder produced during the step. Called at step teardown.
     * Thread-safe: clears the unbinders list after copying.
     */
    public void unbindAll(Run<?, ?> run, FilePath workspace, Launcher launcher,
                          TaskListener listener) throws IOException, InterruptedException {
        List<MultiBinding.Unbinder> copy;
        synchronized (unbinders) {
            copy = new ArrayList<>(unbinders);
            unbinders.clear();
        }
        for (MultiBinding.Unbinder u : copy) {
            u.unbind(run, workspace, launcher, listener);
        }
    }
}
