package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.core.common.ChaosInterceptorFilter.ErrorShape;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ChaosInterceptorFilter}'s protocol-shape resolution and fault response
 * builders. These are the behaviours PR review flagged: a presigned or s3express S3 request must
 * be shaped as S3 XML, and each injected fault must carry the code, status and content type the
 * caller's SDK can parse. No Quarkus context is needed: the methods are static and the request
 * context is mocked.
 */
class ChaosInterceptorFilterTest {

    // ---- resolveShape (finding #3) ----

    @Test
    void queryClaimResolvesToQueryXml() {
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        ctx.claim(new ProtocolClaim(WireProtocol.AWS_QUERY, null, null, null));
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.QUERY_XML));
    }

    @Test
    void jsonClaimResolvesToJson() {
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        ctx.claim(new ProtocolClaim(WireProtocol.AWS_JSON_1_1, descriptor("dynamodb"), "PutItem", null));
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.JSON));
    }

    @Test
    void s3AuthorizationHeaderResolvesToS3Xml() {
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        ctx.authorization("AWS4-HMAC-SHA256 Credential=AKID/20260928/us-east-1/s3/aws4_request, "
                + "SignedHeaders=host, Signature=abc");
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.S3_XML));
    }

    @Test
    void presignedS3ResolvesToS3Xml() {
        // A presigned request carries no Authorization header; its credential scope is in the
        // X-Amz-Credential query parameter. Finding #3: this must still be recognised as S3.
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        ctx.query("X-Amz-Credential", "AKID/20260928/us-east-1/s3/aws4_request");
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.S3_XML));
    }

    @Test
    void s3expressScopeResolvesToS3Xml() {
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        ctx.authorization("AWS4-HMAC-SHA256 Credential=AKID/20260928/us-east-1/s3express/aws4_request, "
                + "SignedHeaders=host, Signature=abc");
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.S3_XML));
    }

    @Test
    void formEncodedNoClaimFallsBackToQueryXml() {
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        ctx.mediaType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.QUERY_XML));
    }

    @Test
    void noSignalsFallBackToJson() {
        ContainerRequestContextStub ctx = new ContainerRequestContextStub();
        assertThat(ChaosInterceptorFilter.resolveShape(ctx.ctx()), equalTo(ErrorShape.JSON));
    }

    // ---- fault response builders (findings #3 shape + #4 no-response) ----

    @Test
    void throttlingResponsesCarryCorrectCodeAndStatus() {
        Response query = ChaosInterceptorFilter.throttlingResponse(ErrorShape.QUERY_XML);
        assertThat(query.getStatus(), equalTo(400));
        assertThat(query.getMediaType().toString(), containsString("xml"));
        assertThat(entityString(query), containsString("Throttling"));

        Response json = ChaosInterceptorFilter.throttlingResponse(ErrorShape.JSON);
        assertThat(json.getStatus(), equalTo(400));
        assertThat(json.getMediaType().toString(), containsString("json"));
        assertThat(json.getHeaderString("X-Amzn-Errortype"), containsString("ThrottlingException"));

        Response s3 = ChaosInterceptorFilter.throttlingResponse(ErrorShape.S3_XML);
        assertThat(s3.getStatus(), equalTo(503));
        assertThat(s3.getMediaType().toString(), containsString("xml"));
        assertThat(entityString(s3), containsString("SlowDown"));
    }

    @Test
    void accessDeniedResponsesCarryCorrectCodeAndStatus() {
        assertThat(ChaosInterceptorFilter.accessDeniedResponse(ErrorShape.QUERY_XML).getStatus(), equalTo(403));
        assertThat(entityString(ChaosInterceptorFilter.accessDeniedResponse(ErrorShape.QUERY_XML)),
                containsString("AccessDenied"));
        assertThat(ChaosInterceptorFilter.accessDeniedResponse(ErrorShape.JSON).getStatus(), equalTo(403));
        assertThat(ChaosInterceptorFilter.accessDeniedResponse(ErrorShape.S3_XML).getStatus(), equalTo(403));
        assertThat(entityString(ChaosInterceptorFilter.accessDeniedResponse(ErrorShape.S3_XML)),
                containsString("AccessDenied"));
    }

    @Test
    void timeoutResponsesForNoResponseCarryCorrectStatus() {
        // Finding #4: no-response aborts with a terminal timeout rather than letting the resource run.
        assertThat(ChaosInterceptorFilter.timeoutResponse(ErrorShape.QUERY_XML).getStatus(), equalTo(504));
        assertThat(ChaosInterceptorFilter.timeoutResponse(ErrorShape.JSON).getStatus(), equalTo(504));
        Response s3 = ChaosInterceptorFilter.timeoutResponse(ErrorShape.S3_XML);
        assertThat(s3.getStatus(), equalTo(400));
        assertThat(entityString(s3), containsString("RequestTimeout"));
    }

    private static String entityString(Response response) {
        return String.valueOf(response.getEntity());
    }

    private static ServiceDescriptor descriptor(String service) {
        return new ServiceDescriptor(service, service, true, true, service, "memory", 0L,
                null, null, Set.of(), Set.of(), Set.of(service), Set.of(), Set.of());
    }

    /** Minimal mocked {@link ContainerRequestContext} exposing only what resolveShape reads. */
    private static final class ContainerRequestContextStub {
        private final ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        private final UriInfo uriInfo = mock(UriInfo.class);
        private final MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();

        ContainerRequestContextStub() {
            when(ctx.getUriInfo()).thenReturn(uriInfo);
            when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        }

        void authorization(String value) {
            when(ctx.getHeaderString("Authorization")).thenReturn(value);
        }

        void query(String name, String value) {
            queryParams.add(name, value);
        }

        void mediaType(MediaType mediaType) {
            when(ctx.getMediaType()).thenReturn(mediaType);
        }

        void claim(ProtocolClaim claim) {
            when(ctx.getProperty(AwsProtocolClaimFilter.CLAIM_PROPERTY)).thenReturn(claim);
        }

        ContainerRequestContext ctx() {
            return ctx;
        }
    }
}
