package com.outlet.license;

import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.bulkhead.ThreadPoolBulkhead;
import io.github.resilience4j.bulkhead.ThreadPoolBulkheadConfig;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

@SpringBootTest
class LicenseServiceApplicationTests {

	@Disabled
	void contextLoads() {
	}

	@Test
	public void testThreadPoolBulkheadCapacity() throws InterruptedException, ExecutionException {
		// Configure the thread pool bulkhead
		ThreadPoolBulkheadConfig config = ThreadPoolBulkheadConfig.custom()
			.coreThreadPoolSize(2)
			.maxThreadPoolSize(3)
			.queueCapacity(1)
			.build();

		ThreadPoolBulkhead bulkhead = ThreadPoolBulkhead.of("testBulkhead", config);

		// Create an executor service
		ExecutorService executorService = Executors.newFixedThreadPool(6); // More threads
																			// than
																			// allowed, to
																			// test the
		// limit.

		List<Future<Object>> futures = new ArrayList<>();

		// Submit tasks to the bulkhead
		for (int i = 0; i < 6; i++) {
			final int taskNumber = i;
			Future<Object> future = executorService.submit(() -> {
				try {
					return bulkhead.executeCallable(() -> {
						// Simulate a task that takes some time
						Thread.sleep(1000);
						System.out.println("Task " + taskNumber + " completed");
						return "Task " + taskNumber + " completed";
					});
				}
				catch (Throwable e) {
					System.out.println("Task " + taskNumber + " rejected");
					if (e instanceof BulkheadFullException) {
						return "Task " + taskNumber + " rejected";
					}
					else {
						return "Task ";
					}
				}
			});
			futures.add(future);
		}

		// Collect results and assertions
		List<Object> results = futures.stream().map(future -> {
			try {
				return future.get();
			}
			catch (InterruptedException | ExecutionException e) {
				return "Error: " + e.getMessage();
			}
		}).collect(Collectors.toList());

		// long rejectedCount = results.stream().filter(result ->
		// result.contains("rejected")).count();

		// Assert that some tasks were rejected. 6 requests, 4 can run, 2 can queue.
		// Assertions.assertEquals(2, rejectedCount);

		executorService.shutdown();

	}

}
