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

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;

/**
 * Global configuration listing the credentials that should be re-resolved on every step of a
 * {@code withCredentials}/{@code environment{}} block instead of being cached once at block start.
 *
 * <p>Some credential types mint a short-lived secret on each read (for example a GitHub App
 * installation token, which expires after one hour). In a long-running build the cached secret goes
 * stale mid-block and later steps fail with an expired token. Marking such a credential here makes its
 * binding re-resolve per step so every step sees a fresh value, while all rotated values stay masked.
 *
 * <p>The selection is a repeatable list of credential pickers. An empty selection means
 * {@link #isRefreshing(String)} always returns {@code false}, i.e. every credential keeps the exact
 * stock (upstream) caching behavior.
 */
@Extension
public class RefreshBindingConfiguration extends GlobalConfiguration {

    /** The admin-selected entries, each pointing at one credentials id to refresh per step. */
    private List<Entry> entries = new ArrayList<>();

    /** Derived, immutable view of the selected credential ids; recomputed on every change. */
    private transient volatile Set<String> ids = Collections.emptySet();

    public RefreshBindingConfiguration() {
        load();
        reparse();
    }

    public static RefreshBindingConfiguration get() {
        return GlobalConfiguration.all().get(RefreshBindingConfiguration.class);
    }

    @NonNull
    public List<Entry> getEntries() {
        return entries == null ? Collections.emptyList() : Collections.unmodifiableList(entries);
    }

    @DataBoundSetter
    public void setEntries(List<Entry> entries) {
        this.entries = entries == null ? new ArrayList<>() : new ArrayList<>(entries);
        reparse();
        save();
    }

    /**
     * Convenience setter to select the refreshed credentials by id (used by JCasC-style code and by
     * tests). Blank/null ids are ignored.
     */
    public void setCredentialIds(Collection<String> credentialIds) {
        List<Entry> list = new ArrayList<>();
        if (credentialIds != null) {
            for (String id : credentialIds) {
                if (id != null && !id.isEmpty()) {
                    list.add(new Entry(id));
                }
            }
        }
        setEntries(list);
    }

    /** @return the immutable set of credential ids selected for per-step refresh. */
    public Set<String> getCredentialIds() {
        return ids;
    }

    /**
     * @param credentialsId a credential id, possibly {@code null}
     * @return {@code true} iff this id was selected for per-step refresh; always {@code false} when the
     *         selection is empty (stock behavior).
     */
    public boolean isRefreshing(String credentialsId) {
        return credentialsId != null && !credentialsId.isEmpty() && ids.contains(credentialsId);
    }

    private void reparse() {
        Set<String> parsed = new LinkedHashSet<>();
        if (entries != null) {
            for (Entry e : entries) {
                String id = e == null ? null : e.getCredentialsId();
                if (id != null && !id.isEmpty()) {
                    parsed.add(id);
                }
            }
        }
        this.ids = Collections.unmodifiableSet(parsed);
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws FormException {
        // Reset first so entries removed in the UI are cleared (a repeatable list omits the key when empty).
        this.entries = new ArrayList<>();
        req.bindJSON(this, json);
        reparse();
        save();
        return true;
    }

    /**
     * A single selected credential. Backed by a credentials picker in the UI so admins choose from the
     * store instead of typing an id by hand.
     */
    public static class Entry extends AbstractDescribableImpl<Entry> {

        private final String credentialsId;

        @DataBoundConstructor
        public Entry(String credentialsId) {
            this.credentialsId = credentialsId;
        }

        public String getCredentialsId() {
            return credentialsId;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<Entry> {

            @NonNull
            @Override
            public String getDisplayName() {
                return "";
            }

            /**
             * Populates the credentials dropdown from the system-scope store. This is a global
             * configuration with no item context, so credentials are looked up over {@link Jenkins}
             * itself at system scope. Requires the {@code ADMINISTER} permission to enumerate.
             */
            public ListBoxModel doFillCredentialsIdItems(@QueryParameter String credentialsId) {
                Jenkins jenkins = Jenkins.get();
                if (!jenkins.hasPermission(Jenkins.ADMINISTER)) {
                    return new StandardListBoxModel().includeCurrentValue(credentialsId);
                }
                return new StandardListBoxModel()
                        .includeEmptyValue()
                        .includeMatchingAs(
                                ACL.SYSTEM2,
                                jenkins,
                                StandardCredentials.class,
                                Collections.emptyList(),
                                CredentialsMatchers.always())
                        .includeCurrentValue(credentialsId);
            }
        }
    }
}
