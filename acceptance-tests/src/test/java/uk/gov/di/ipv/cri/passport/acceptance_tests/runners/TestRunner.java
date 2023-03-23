package uk.gov.di.ipv.cri.passport.acceptance_tests.runners;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;
import org.junit.runner.RunWith;

@RunWith(Cucumber.class)
@CucumberOptions(
        publish = true,
        plugin = "io.qameta.allure.cucumber7jvm.AllureCucumber7Jvm",
        features = "src/test/resources/features",
        glue = "uk/gov/di/ipv/cri/passport/acceptance_tests/step_definitions",
        dryRun = false)
public class TestRunner {}
