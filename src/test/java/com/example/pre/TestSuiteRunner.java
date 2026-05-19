package com.example.pre;

import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

public final class TestSuiteRunner {
    private TestSuiteRunner() {
    }

    public static void main(String[] args) {
        CountingListener listener = new CountingListener();
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
                .selectors(DiscoverySelectors.selectPackage("com.example.pre"))
                .build();
        Launcher launcher = LauncherFactory.create();
        launcher.registerTestExecutionListeners(listener);
        launcher.execute(request);
        System.out.println("Tests run: " + listener.tests + ", Failures: " + listener.failures);
        if (listener.failures > 0 || listener.tests == 0) {
            throw new IllegalStateException("JUnit suite failed");
        }
    }

    private static final class CountingListener implements TestExecutionListener {
        int tests;
        int failures;

        @Override
        public void testPlanExecutionStarted(TestPlan testPlan) {
            tests = 0;
            failures = 0;
        }

        @Override
        public void executionFinished(TestIdentifier testIdentifier, org.junit.platform.engine.TestExecutionResult result) {
            if (testIdentifier.isTest()) {
                tests++;
                if (result.getStatus() == org.junit.platform.engine.TestExecutionResult.Status.FAILED) {
                    failures++;
                    result.getThrowable().ifPresent(Throwable::printStackTrace);
                }
            }
        }
    }
}
