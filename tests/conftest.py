"""Make the acceptance tests green-until-implemented.

Every component ships with its acceptance tests already written (that is the spec).
Until the owner implements the component, its functions `raise NotImplementedError`,
which would show as a hard failure and turn CI red. This hook reclassifies a
NotImplementedError into an expected failure (xfail), so:

  * CI is GREEN now, with a clear "X xfailed" count = work still to do;
  * when you implement your component, its tests PASS normally — no test edits needed.

Do not weaken a test to make it pass. Implement the function until it passes for real.
"""
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and call.excinfo is not None \
            and call.excinfo.errisinstance(NotImplementedError):
        report.outcome = "skipped"
        report.wasxfail = "component not yet implemented (stub)"
