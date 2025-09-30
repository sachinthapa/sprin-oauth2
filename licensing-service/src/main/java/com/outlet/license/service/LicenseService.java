package com.optimagrowth.license.service;

import com.optimagrowth.license.config.ServiceConfig;
import com.optimagrowth.license.model.License;
import com.optimagrowth.license.model.Organization;
import com.optimagrowth.license.repository.LicenseRepository;
import com.optimagrowth.license.service.client.OrganizationDiscoveryClient;
import com.optimagrowth.license.service.client.OrganizationFeignClient;
import com.optimagrowth.license.service.client.OrganizationRestTemplateClient;
import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.bulkhead.BulkheadRegistry;
import io.github.resilience4j.bulkhead.ThreadPoolBulkheadRegistry;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.github.resilience4j.retry.RetryRegistry;
import io.github.resilience4j.retry.annotation.Retry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeoutException;

@Service
public class LicenseService {

    @Autowired
    MessageSource messages;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    ServiceConfig config;

    @Autowired
    OrganizationFeignClient organizationFeignClient;

    @Autowired
    OrganizationRestTemplateClient organizationRestClient;

    @Autowired
    OrganizationDiscoveryClient organizationDiscoveryClient;

    private static final Logger logger = LoggerFactory.getLogger(LicenseService.class);

    public License getLicense(String licenseId, String organizationId, String clientType) {
        License license = licenseRepository.findByOrganizationIdAndLicenseId(UUID.fromString(organizationId),
                UUID.fromString(licenseId));
        if (null == license) {
            throw new IllegalArgumentException(String
                    .format(messages.getMessage("license.search.error.message", null, null), licenseId,
                            organizationId));
        }
        Organization organization = retrieveOrganizationInfo(organizationId, clientType);
        if (null != organization) {
            license.setOrganizationName(organization.getName());
            license.setContactName(organization.getContactName());
            license.setContactEmail(organization.getContactEmail());
            license.setContactPhone(organization.getContactPhone());
        }
        return license.withComment(config.getProperty());
    }

    private Organization retrieveOrganizationInfo(String organizationId, String clientType) {
        Organization organization = null;

        switch (clientType) {
            case "feign":
                organization = organizationFeignClient.getOrganization(organizationId);
                break;
            case "rest":
                organization = organizationRestClient.getOrganizationWithDefaultAuthorizedClient(organizationId);
                break;
            case "discovery":
                organization = organizationDiscoveryClient.getOrganization(organizationId);
                break;
            default:
                organization = organizationRestClient.getOrganizationWithDefaultAuthorizedClient(organizationId);
                break;
        }
        return organization;
    }

    public License createLicense(License license) {
        license.setLicenseId(UUID.randomUUID());
        licenseRepository.save(license);
        return license.withComment(config.getProperty());
    }

    public License updateLicense(License license) {
        licenseRepository.save(license);
        return license.withComment(config.getProperty());
    }

    public String deleteLicense(String licenseId) {
        String responseMessage = null;
        License license = new License();
        license.setLicenseId(UUID.fromString(licenseId));
        licenseRepository.delete(license);
        responseMessage = String.format(messages.getMessage("license.delete.message", null, null), licenseId);
        return responseMessage;
    }

    @CircuitBreaker(name = "licenseService")
    @RateLimiter(name = "licenseService")
    @Retry(name = "retryLicenseService", fallbackMethod = "fallback")
    @Bulkhead(name = "threadPoolBulkheadLicenseService", type = Bulkhead.Type.THREADPOOL)
    public CompletableFuture<List<License>> getLicensesByOrganization(String organizationId, int sleep)
            throws RuntimeException {
        CompletableFuture<List<License>> future = new CompletableFuture<>();
        CompletableFuture.runAsync(() -> {
            try {
                if (sleep % 2 == 0)
                    randomlyRunLong();
                future.complete(licenseRepository.findByOrganizationId(UUID.fromString(organizationId)));
            } catch (Exception e) {
                future.completeExceptionally(new TimeoutException("Operation timed out"));
            }
            // logger.debug("testRetry: {}", testRetry());
        });
        return future;
    }

    private void randomlyRunLong() throws TimeoutException {
        int randomNum = ThreadLocalRandom.current().nextInt(1, 6);
        sleep();
        if (randomNum % 2 == 0) {
            throw new TimeoutException();
        }
    }

    private void sleep() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            logger.error(e.getMessage());
        }
    }

    @SuppressWarnings("unused")
    private CompletableFuture<List<License>> fallback(String organizationId, int sleep, BulkheadFullException t) {
        return CompletableFuture.supplyAsync(() -> new ArrayList<>() {
            {
                License license = new License();
                license.setComment(t.getMessage());
                license.setProductName("BulkheadFullException");
                add(license);
            }
        });
    }

    @SuppressWarnings("unused")
    private CompletableFuture<List<License>> fallback(String organizationId, int sleep, CallNotPermittedException t) {
        return CompletableFuture.supplyAsync(() -> new ArrayList<>() {
            {
                License license = new License();
                license.setComment(t.getMessage());
                license.setProductName("CallNotPermittedException");
                add(license);
            }
        });
    }

    @SuppressWarnings("unused")
    private CompletableFuture<List<License>> fallback(String organizationId, int sleep, RequestNotPermitted t) {
        return CompletableFuture.supplyAsync(() -> new ArrayList<>() {
            {
                License license = new License();
                license.setComment(t.getMessage());
                license.setProductName("RequestNotPermitted");
                add(license);
            }
        });
    }

    @SuppressWarnings("unused")
    private CompletableFuture<List<License>> fallback(String organizationId, int sleep, TimeoutException t) {
        return CompletableFuture.supplyAsync(() -> new ArrayList<>() {
            {
                License license = new License();
                license.setComment(t.getMessage());
                license.setProductName("TimeoutException:");
                add(license);
            }
        });
    }

    @Autowired
    private RateLimiterRegistry rateLimiterRegistry;

    @Autowired
    private RetryRegistry retryRegistry;

    @Autowired
    private BulkheadRegistry bulkheadRegistry;

    @Autowired
    private ThreadPoolBulkheadRegistry threadPoolBulkheadRegistry;

    @PostConstruct
    public void postConstruct() {
        // setBulkheadRegistry();
        setRetryRegistry();
    }

    public void setRetryRegistry() {
        var eventPublisher = retryRegistry.retry("retryLicenseService").getEventPublisher();
        eventPublisher.onEvent(event -> System.out.println("onEvent " + event));
        eventPublisher.onError(event -> System.out.println("onError " + event));
        eventPublisher.onSuccess(event -> System.out.println("onSuccess " + event));
        eventPublisher.onRetry(event -> System.out.println("onRetry " + event));
    }

    public void setBulkheadRegistry() {
        var eventPublisher = bulkheadRegistry.bulkhead("threadPoolBulkheadLicenseService").getEventPublisher();
        eventPublisher.onEvent(
                event -> System.out.println("Bulkhead with concurrent calls - On Event." + " Event Details: " + event));
        eventPublisher.onCallPermitted(event -> System.out
                .println("Bulkhead with concurrent calls  - On call " + "permitted. Event Details: " + event));
        eventPublisher.onCallRejected(event -> System.out
                .println("Bulkhead with concurrent calls  - On call rejected" + ". Event Details: " + event));
        eventPublisher.onCallFinished(event -> System.out
                .println("Bulkhead with concurrent calls  - On call" + " finished Event Details:" + event));

        // bulkheadRegistry.getEventPublisher().onEntryAdded(entryAddedEvent -> {
        // var addedBulkhead = entryAddedEvent.getAddedEntry();
        // System.out.println("Bulkhead added: " + addedBulkhead.getName());
        // })
        // .onEntryRemoved(entryRemovedEvent -> {
        // var removedBulkhead = entryRemovedEvent.getRemovedEntry();
        // System.out.println("Bulkhead removed: " + removedBulkhead.getName());
        // })
        // .onEntryReplaced(entryReplacedEvent -> {
        // var oldBulkhead = entryReplacedEvent.getOldEntry();
        // var newBulkhead = entryReplacedEvent.getNewEntry();
        // System.out.println("Bulkhead " + oldBulkhead + " replaced with " +
        // newBulkhead);
        // });
    }

    public String testRateLimiterRegistry() {
        var bulkhead = rateLimiterRegistry.rateLimiter("licenseService");
        return String.format("""
                        testRateLimiterRegistry - \
                        getNumberOfWaitingThreads: %d, \
                        getAvailablePermissions: %s, \
                        getLimitRefreshPeriod: %s""", bulkhead.getMetrics().getNumberOfWaitingThreads(),
                bulkhead.getMetrics().getAvailablePermissions(),
                bulkhead.getRateLimiterConfig().getLimitRefreshPeriod());
    }

    public String testRetry() {
        var bulkhead = retryRegistry.retry("retryLicenseService");
        return String.format("""
                        ========> retryRegistry
                         getNumberOfFailedCallsWithRetryAttempt: %d,
                         getNumberOfSuccessfulCallsWithRetryAttempt: %d,
                         getNumberOfTotalCalls: %d""", bulkhead.getMetrics().getNumberOfFailedCallsWithRetryAttempt(),
                bulkhead.getMetrics().getNumberOfSuccessfulCallsWithRetryAttempt(),
                bulkhead.getMetrics().getNumberOfTotalCalls());
    }

    public String testBulkhead() {
        var bulkhead = bulkheadRegistry.bulkhead("bulkheadLicenseService");
        return String.format("Metrics - ConcurrentCalls: %d, MaxConcurrentCalls: %d, MaxWaitDuration: %s ",
                bulkhead.getMetrics().getAvailableConcurrentCalls(),
                bulkhead.getMetrics().getMaxAllowedConcurrentCalls(),
                bulkhead.getBulkheadConfig().getMaxWaitDuration());
    }

    public String testThreadPoolBulkhead() {
        var bulkhead = threadPoolBulkheadRegistry.bulkhead("threadPoolBulkheadLicenseService");
        return String.format("Metrics - Available: %d, Queue: %d/%d, Core: %d, Max: %d",
                bulkhead.getMetrics().getAvailableThreadCount(), bulkhead.getMetrics().getRemainingQueueCapacity(),
                bulkhead.getMetrics().getQueueCapacity(), bulkhead.getBulkheadConfig().getCoreThreadPoolSize(),
                bulkhead.getBulkheadConfig().getMaxThreadPoolSize());
    }

}
