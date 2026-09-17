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
import hudson.Functions;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;
import org.jenkinsci.plugins.workflow.steps.FailureHandler;
import org.jenkinsci.plugins.workflow.steps.StepContext;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A {@link FailureHandler} that masks refreshing (selected) secrets on the exception/failure surface.
 *
 * <p>The stock {@code Handler} masks only the eagerly-resolved stock secrets, and the union-masking
 * {@link RefreshingFilter} only covers the CONSOLE. But a thrown exception is wrapped into a
 * {@code MaskedException} that populates the FlowNode {@code ErrorAction}, which is rendered in the
 * build UI / stage view / {@code /wfapi} REST and is reachable from pipeline {@code catch(e){ e.getMessage() }}
 * — surfaces that do NOT pass through the {@code ConsoleLogFilter}. Without this handler, a rotated
 * refreshing token embedded in an exception message (e.g. {@code 401 ...?token=<tok>}) would leak there.
 *
 * <p>The mask is driven by the {@link RefreshingFilter}'s LIVE secret set ({@link RefreshingFilter#knownSecrets()})
 * evaluated at failure time, because refreshing secrets are only known after the body's steps have resolved them.
 */
public class RefreshingFailureHandler implements FailureHandler {

    private static final long serialVersionUID = 1L;

    private final RefreshingFilter filter;

    public RefreshingFailureHandler(RefreshingFilter filter) {
        this.filter = filter;
    }

    @NonNull
    @Override
    public Throwable handle(@NonNull StepContext context, @NonNull Throwable t) {
        Set<String> secrets = filter.knownSecrets();
        if (secrets.isEmpty()) {
            return t;
        }
        Pattern pattern = SecretPatterns.getAggregateSecretPattern(secrets);
        if (pattern.pattern().isEmpty()) {
            // No maskable (long-enough) encoded forms; nothing to do.
            return t;
        }
        return mask(t, new HashSet<>(), pattern);
    }

    /**
     * Recursively rewrites the throwable chain (message, cause, suppressed) replacing every match of
     * {@code pattern} with {@code ****}, preserving stack traces. Mirrors the stock {@code MaskedException}
     * behavior (which is package-private and cannot be reused from this package).
     */
    private static Throwable mask(@NonNull Throwable unmasked, @NonNull Set<Throwable> visited, Pattern pattern) {
        if (!visited.add(unmasked)) {
            return new Exception("cycle");
        }
        String text = Functions.printThrowable(unmasked);
        if (pattern.matcher(text).find()) {
            MaskedThrowable masked = new MaskedThrowable(
                    pattern.matcher(Objects.requireNonNullElse(unmasked.getMessage(), "")).replaceAll("****"));
            masked.setStackTrace(unmasked.getStackTrace());
            Throwable cause = unmasked.getCause();
            if (cause != null) {
                masked.initCause(mask(cause, visited, pattern));
            }
            for (Throwable suppressed : unmasked.getSuppressed()) {
                masked.addSuppressed(mask(suppressed, visited, pattern));
            }
            return masked;
        }
        return unmasked;
    }

    /** Masked replacement for a throwable whose text contained a refreshing secret. */
    private static final class MaskedThrowable extends Exception {
        private static final long serialVersionUID = 1L;

        MaskedThrowable(String message) {
            super(message);
        }
    }
}
