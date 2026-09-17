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

import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;

import java.io.ObjectStreamException;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A {@link ConsoleLogFilter} that masks the union of all secret values it has ever been given.
 * When credentials are rotated, both the old and new values remain masked in the logs.
 * The filter is serializable so it can travel with the step context to remote agents.
 */
public class RefreshingFilter extends ConsoleLogFilter implements Serializable {
    private static final long serialVersionUID = 1L;

    private final Set<String> secrets = Collections.synchronizedSet(new LinkedHashSet<>());

    /** Charset used when decoding console bytes for masking. Mirrors the stock {@code Filter}. */
    private String charsetName;

    /**
     * Cached aggregate pattern. Marked transient because Pattern is not Serializable.
     * Recompiled lazily after deserialization or when secrets are added.
     */
    private transient volatile Pattern pattern;

    /** Defaults the charset to UTF-8 (kept for existing callers/tests). */
    public RefreshingFilter() {
        this(StandardCharsets.UTF_8.name());
    }

    /**
     * @param charsetName the console charset (typically {@code run.getCharset().name()}), so
     *                    refreshing secrets mask correctly on non-UTF-8 consoles.
     */
    public RefreshingFilter(String charsetName) {
        this.charsetName = charsetName == null ? StandardCharsets.UTF_8.name() : charsetName;
    }

    // Keep de-serialization safe for instances persisted before charsetName existed.
    private Object readResolve() throws ObjectStreamException {
        if (this.charsetName == null) {
            this.charsetName = StandardCharsets.UTF_8.name();
        }
        return this;
    }

    /**
     * Adds a secret to the union set. If the secret is new, recompiles the masking pattern.
     *
     * @param secret the secret value to mask (ignored if null or empty)
     */
    public void add(String secret) {
        if (secret == null || secret.isEmpty()) {
            return;
        }
        boolean changed;
        synchronized (secrets) {
            changed = secrets.add(secret);
        }
        if (changed) {
            recompile();
        }
    }

    /**
     * Returns a snapshot of all secrets currently known to this filter.
     *
     * @return an immutable copy of the secrets set
     */
    public Set<String> knownSecrets() {
        synchronized (secrets) {
            return new LinkedHashSet<>(secrets);
        }
    }

    private void recompile() {
        Set<String> snapshot;
        synchronized (secrets) {
            snapshot = new LinkedHashSet<>(secrets);
        }
        pattern = snapshot.isEmpty() ? null
            : SecretPatterns.getAggregateSecretPattern(snapshot);
    }

    /**
     * Decorates the logger with a MaskingOutputStream that masks all known secrets.
     * The pattern is supplied lazily via a Supplier so that secrets added after decoration
     * (e.g., during credential rotation) are still masked.
     *
     * @param build the build (unused)
     * @param logger the base output stream
     * @return a masking output stream, or the original logger if no secrets are known
     */
    @Override
    public OutputStream decorateLogger(Run build, OutputStream logger) {
        // Ensure pattern is compiled if we were just deserialized
        if (pattern == null && !secrets.isEmpty()) {
            recompile();
        }

        Pattern p = pattern;
        if (p == null) {
            return logger;
        }

        // MaskingOutputStream reads the (volatile) pattern via this supplier so
        // rotations added after decoration are still masked.
        return new SecretPatterns.MaskingOutputStream(logger, () -> pattern, charsetName);
    }
}
