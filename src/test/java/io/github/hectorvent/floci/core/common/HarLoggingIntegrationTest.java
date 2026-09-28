package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@QuarkusTest
@TestProfile(HarLoggingIntegrationTest.HarProfile.class)
class HarLoggingIntegrationTest {

    private static final Path HAR_FILE = Path.of("target", "test-har", "har-logging-test.har");

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * The Query POST body has to reach {@code postData.text}. Reading it in the pre-matching
     * filter threw {@code BlockingNotAllowedException} on the Vert.x IO thread, which dropped
     * every request carrying a body from the log and left only bodyless ones, so a HAR holding
     * the GET but not the POST is the regression this guards.
     */
    @Test
    void queryPostBodyAndResponseAreRecorded() throws IOException {
        given()
        .when()
            .get("/")
        .then()
            .statusCode(200);

        given()
            .contentType("application/x-www-form-urlencoded")
            .body("Action=ListQueues&Version=2012-11-05")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        JsonNode log = objectMapper.readTree(Files.readString(HAR_FILE)).path("log");
        assertThat(log.path("version").asText(), equalTo("1.2"));

        JsonNode postEntry = findEntry(log, "POST", "Action=ListQueues");
        assertNotNull(postEntry, "HAR has no POST entry carrying the form-encoded body: " + log.path("entries"));
        assertThat(postEntry.path("request").path("postData").path("mimeType").asText(),
                containsString("application/x-www-form-urlencoded"));
        assertThat(postEntry.path("request").path("postData").path("text").asText(),
                containsString("Version=2012-11-05"));
        assertThat(postEntry.path("request").path("bodySize").asInt(), is(not(0)));
        assertThat(postEntry.path("response").path("status").asInt(), equalTo(200));
        assertThat(postEntry.path("response").path("content").path("text").asText(),
                containsString("ListQueuesResponse"));

        JsonNode getEntry = findEntry(log, "GET", null);
        assertNotNull(getEntry, "HAR has no bodyless GET entry");
        assertThat(getEntry.path("request").has("postData"), is(false));
    }

    private static JsonNode findEntry(JsonNode log, String method, String bodyFragment) {
        for (JsonNode entry : log.path("entries")) {
            JsonNode request = entry.path("request");
            if (!method.equals(request.path("method").asText())) {
                continue;
            }
            if (bodyFragment == null) {
                return entry;
            }
            if (request.path("postData").path("text").asText("").contains(bodyFragment)) {
                return entry;
            }
        }
        return null;
    }

    public static final class HarProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.chaos.enabled", "true",
                    "floci.chaos.har.enabled", "true",
                    "floci.chaos.har.file", HAR_FILE.toString());
        }
    }
}
