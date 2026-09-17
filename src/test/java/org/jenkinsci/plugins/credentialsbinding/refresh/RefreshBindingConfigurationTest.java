package org.jenkinsci.plugins.credentialsbinding.refresh;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class RefreshBindingConfigurationTest {
    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    @Test
    void emptyByDefaultAndNullSafe() {
        RefreshBindingConfiguration c = RefreshBindingConfiguration.get();
        assertTrue(c.getCredentialIds().isEmpty());
        assertTrue(c.getEntries().isEmpty());
        assertFalse(c.isRefreshing(null));
        assertFalse(c.isRefreshing(""));
        assertFalse(c.isRefreshing("anything"));
    }

    @Test
    void matchesSelectedIdsAndPersists() {
        RefreshBindingConfiguration c = RefreshBindingConfiguration.get();
        c.setCredentialIds(List.of("github-app", "other-id"));
        assertTrue(c.isRefreshing("github-app"));
        assertTrue(c.isRefreshing("other-id"));
        assertFalse(c.isRefreshing("nope"));
        assertEquals(Set.of("github-app", "other-id"), c.getCredentialIds());

        // Reloading from disk keeps the selection (setCredentialIds calls save()).
        RefreshBindingConfiguration reloaded = new RefreshBindingConfiguration();
        assertTrue(reloaded.isRefreshing("github-app"));
        assertTrue(reloaded.isRefreshing("other-id"));
    }

    @Test
    void blankAndNullIdsAreIgnored() {
        RefreshBindingConfiguration c = RefreshBindingConfiguration.get();
        c.setCredentialIds(Arrays.asList("keep", "", null));
        assertEquals(Set.of("keep"), c.getCredentialIds());
    }

    @Test
    void entriesRoundTripThroughSelectorModel() {
        RefreshBindingConfiguration c = RefreshBindingConfiguration.get();
        c.setEntries(List.of(
                new RefreshBindingConfiguration.Entry("id-a"),
                new RefreshBindingConfiguration.Entry("id-b")));
        assertEquals(2, c.getEntries().size());
        assertEquals("id-a", c.getEntries().get(0).getCredentialsId());
        assertTrue(c.isRefreshing("id-a"));
        assertTrue(c.isRefreshing("id-b"));

        // Selecting an empty list restores stock behavior.
        c.setEntries(List.of());
        assertTrue(c.getCredentialIds().isEmpty());
        assertFalse(c.isRefreshing("id-a"));
    }
}
