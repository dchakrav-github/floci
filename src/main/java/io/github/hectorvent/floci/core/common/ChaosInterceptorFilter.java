package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.config.EmulatorConfig.ChaosConfig;
import io.github.hectorvent.floci.config.EmulatorConfig.ChaosConfig.ChaosFaultConfig;
import io.github.hectorvent.floci.config.EmulatorConfig.ChaosConfig.ChaosNetworkConfig;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.util.Random;
import java.util.UUID;

/**
 * Injects faults and network conditions into inbound requests when
 * {@code floci.chaos.enabled = true} ({@code FLOCI_CHAOS_ENABLED=true} in the environment).
 * Every probability defaults to 0.0, so enabling the master switch alone changes nothing.
 *
 * <p>Runs at priority 6500 and deliberately not pre-matching, so {@link AwsProtocolClaimFilter}
 * (pre-matching, 6000) has already resolved the wire protocol onto
 * {@link AwsProtocolClaimFilter#CLAIM_PROPERTY}. The injected error is then shaped for that
 * protocol, because AWS SDKs hard-fail on the wrong shape: an XML parser blows up on a leading
 * <code>{</code> and a JSON parser on a leading {@code <}. The shapes mirror
 * {@link IamEnforcementFilter}'s builders.
 *
 * <p>One roll per condition, in this order:
 * <ul>
 *   <li>latency: sleeps {@code floci.chaos.network.latency-ms} and lets the request proceed</li>
 *   <li>no response: a bounded sleep standing in for a dropped connection, then a terminal
 *       timeout error so the resource never runs (see {@link #simulateNoResponse})</li>
 *   <li>throttle: aborts with the protocol's throttling error</li>
 *   <li>access denied: aborts with the protocol's access-denied error</li>
 *   <li>generic fault: aborts with throttling, the default injected fault</li>
 * </ul>
 *
 * <p>The sleeps block the serving thread on purpose, which is the point of a latency simulator.
 * Nothing here should ever be enabled in a deployment that is serving real work.
 */
@Provider
@Priority(6500)
public class ChaosInterceptorFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(ChaosInterceptorFilter.class);

    private static final String THROTTLE_MESSAGE = "Rate exceeded";
    private static final String ACCESS_DENIED_MESSAGE = "Access denied by Floci chaos injection";
    private static final String NO_RESPONSE_MESSAGE = "Request timed out (Floci chaos no-response injection)";

    /**
     * How much longer than the configured latency a "no response" waits. The stand-in is a long
     * sleep rather than a real hang: a JAX-RS filter that never returns holds its serving thread
     * for the lifetime of the process, which leaks the thread and eventually starves the server,
     * so the client has to be the one that gives up. The wait is bounded by
     * {@link #NO_RESPONSE_MAX_MS} regardless of the configured latency.
     */
    private static final long NO_RESPONSE_FACTOR = 60;
    private static final long NO_RESPONSE_DEFAULT_MS = 30_000;
    private static final long NO_RESPONSE_MAX_MS = 120_000;

    /**
     * An instance field, not a static one, so no {@code --initialize-at-run-time} entry is needed:
     * the provider is constructed at runtime, so its seed is never captured into the native image.
     */
    private final Random random = new Random();

    // jakarta.inject.Provider qualified inline: this file imports jakarta.ws.rs.ext.Provider,
    // the JAX-RS annotation, and the two types collide. Resolved lazily for the same reason as
    // AwsProtocolClaimFilter: JAX-RS providers are instantiated before runtime config mappings
    // exist.
    private final jakarta.inject.Provider<EmulatorConfig> configProvider;

    @Inject
    public ChaosInterceptorFilter(jakarta.inject.Provider<EmulatorConfig> configProvider) {
        this.configProvider = configProvider;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        ChaosConfig chaos = configProvider.get().chaos();
        if (!chaos.enabled()) {
            return;
        }
        ChaosNetworkConfig network = chaos.network();
        ChaosFaultConfig fault = chaos.fault();

        if (rolls(network.latencyProbability())) {
            LOG.debugv("Chaos: injecting {0}ms latency into {1} {2}",
                    network.latencyMs(), ctx.getMethod(), ctx.getUriInfo().getPath());
            sleep(network.latencyMs());
        }

        InjectedFault injected = selectFault(network, fault);
        if (injected == InjectedFault.NONE) {
            return;
        }
        LOG.debugv("Chaos: injecting {0} into {1} {2}",
                injected, ctx.getMethod(), ctx.getUriInfo().getPath());

        switch (injected) {
            case NO_RESPONSE -> ctx.abortWith(simulateNoResponse(network.latencyMs(), resolveShape(ctx)));
            case THROTTLE -> ctx.abortWith(throttlingResponse(resolveShape(ctx)));
            case ACCESS_DENIED -> ctx.abortWith(accessDeniedResponse(resolveShape(ctx)));
            case NONE -> {
                // Unreachable: returned above.
            }
        }
    }

    /**
     * The first condition whose roll fires, checked in the documented order. The generic
     * {@code fault-probability} maps to {@link InjectedFault#THROTTLE}, the default injected
     * fault, so a caller who only wants "something goes wrong sometimes" gets a retryable error.
     */
    private InjectedFault selectFault(ChaosNetworkConfig network, ChaosFaultConfig fault) {
        if (rolls(network.noResponseProbability())) {
            return InjectedFault.NO_RESPONSE;
        }
        if (rolls(fault.throttleProbability())) {
            return InjectedFault.THROTTLE;
        }
        if (rolls(fault.accessDeniedProbability())) {
            return InjectedFault.ACCESS_DENIED;
        }
        if (rolls(fault.faultProbability())) {
            return InjectedFault.THROTTLE;
        }
        return InjectedFault.NONE;
    }

    private boolean rolls(double probability) {
        if (probability <= 0.0) {
            return false;
        }
        return probability >= 1.0 || random.nextDouble() < probability;
    }

    /**
     * Stands in for a dropped connection: holds the request long past any client timeout, then
     * ABORTS it so the resource never runs. Aborting rather than proceeding is deliberate. If the
     * request were allowed through after the sleep, a client that already timed out and retried a
     * mutating request would have the delayed original also perform its mutation, causing
     * duplicate effects. The bounded sleep still simulates the client-visible hang (a real
     * never-returning filter would leak the serving thread; see {@link #NO_RESPONSE_FACTOR}), and
     * the terminal error is shaped for the caller's protocol so an SDK that is still waiting can
     * parse the timeout rather than choke on an unexpected body.
     */
    private static Response simulateNoResponse(long latencyMs, ErrorShape shape) {
        long requested = latencyMs > 0 ? latencyMs * NO_RESPONSE_FACTOR : NO_RESPONSE_DEFAULT_MS;
        sleep(Math.min(requested, NO_RESPONSE_MAX_MS));
        return timeoutResponse(shape);
    }

    private static void sleep(long millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            LOG.debugv(e, "Chaos: sleep of {0}ms interrupted", millis);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * The error shape this request's caller can parse. S3 is detected first, keyed off the signing
     * service in either the {@code Authorization} header or, for a presigned request, the
     * {@code X-Amz-Credential} query parameter (which is where a presigned request carries its
     * credential scope, absent from any header). Both the {@code s3} scope and the
     * {@code s3express} scope map to S3 XML. Otherwise the shape comes from the protocol claim,
     * falling back to the form-encoded sniff when no claim was made.
     */
    static ErrorShape resolveShape(ContainerRequestContext ctx) {
        if (isS3SigningScope(signingService(ctx))) {
            return ErrorShape.S3_XML;
        }
        if (ctx.getProperty(AwsProtocolClaimFilter.CLAIM_PROPERTY) instanceof ProtocolClaim claim
                && claim.protocol() != null) {
            if (claim.protocol() == WireProtocol.AWS_QUERY) {
                return ErrorShape.QUERY_XML;
            }
            if (claim.service() != null && isS3SigningScope(claim.service().externalKey())) {
                return ErrorShape.S3_XML;
            }
            return ErrorShape.JSON;
        }
        return isFormEncoded(ctx.getMediaType()) ? ErrorShape.QUERY_XML : ErrorShape.JSON;
    }

    /** The SigV4 signing service, from the Authorization header or a presigned X-Amz-Credential. */
    private static String signingService(ContainerRequestContext ctx) {
        return SigV4CredentialScope.serviceName(ctx.getHeaderString("Authorization"))
                .or(() -> SigV4CredentialScope.serviceNameFromCredential(
                        ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential")))
                .orElse(null);
    }

    /** S3 and S3 Express both answer with S3 XML; both sign under an S3-family scope. */
    private static boolean isS3SigningScope(String service) {
        return "s3".equals(service) || "s3express".equals(service);
    }

    private static boolean isFormEncoded(MediaType mediaType) {
        return mediaType != null
                && "application".equalsIgnoreCase(mediaType.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mediaType.getSubtype());
    }

    /** S3 answers a throttle with {@code SlowDown} and 503, every other protocol with a 400. */
    static Response throttlingResponse(ErrorShape shape) {
        return switch (shape) {
            case QUERY_XML -> queryXmlError("Throttling", THROTTLE_MESSAGE, 400);
            case JSON -> jsonError("ThrottlingException", THROTTLE_MESSAGE, 400);
            case S3_XML -> s3XmlError("SlowDown", THROTTLE_MESSAGE, 503);
        };
    }

    static Response accessDeniedResponse(ErrorShape shape) {
        return switch (shape) {
            case QUERY_XML -> queryXmlError("AccessDenied", ACCESS_DENIED_MESSAGE, 403);
            case JSON -> jsonError("AccessDeniedException", ACCESS_DENIED_MESSAGE, 403);
            case S3_XML -> s3XmlError("AccessDenied", ACCESS_DENIED_MESSAGE, 403);
        };
    }

    /**
     * The terminal error for a simulated no-response, once the bounded hang has elapsed. S3 uses
     * its {@code RequestTimeout} (400); other protocols use a 504 gateway-timeout-style error, the
     * closest retryable shape their SDKs recognise for "the request did not complete in time".
     */
    static Response timeoutResponse(ErrorShape shape) {
        return switch (shape) {
            case QUERY_XML -> queryXmlError("RequestTimeout", NO_RESPONSE_MESSAGE, 504);
            case JSON -> jsonError("RequestTimeoutException", NO_RESPONSE_MESSAGE, 504);
            case S3_XML -> s3XmlError("RequestTimeout", NO_RESPONSE_MESSAGE, 400);
        };
    }

    private static Response queryXmlError(String code, String message, int status) {
        String xml = new XmlBuilder()
                .start("ErrorResponse")
                  .start("Error")
                    .elem("Type", "Sender")
                    .elem("Code", code)
                    .elem("Message", message)
                  .end("Error")
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("ErrorResponse")
                .build();
        return Response.status(status).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response s3XmlError(String code, String message, int status) {
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", code)
                  .elem("Message", message)
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("Error")
                .build();
        return Response.status(status).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response jsonError(String code, String message, int status) {
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .header("x-amzn-query-error", code + ";Sender")
                // rest-json SDKs resolve the error code from this header before the body __type
                .header("X-Amzn-Errortype", code)
                .entity(new AwsErrorResponse(code, message))
                .build();
    }

    private enum InjectedFault {
        NONE,
        NO_RESPONSE,
        THROTTLE,
        ACCESS_DENIED
    }

    enum ErrorShape {
        QUERY_XML,
        JSON,
        S3_XML
    }
}
