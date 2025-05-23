package com.optimagrowth.oauth2client;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;

/**
 * Application runtime hints.
 * <p>
 * The native image compiler performs ahead-of-time (AOT) compilation. It analyzes your
 * code and tries to include only the necessary parts in the final executable. By default,
 * it might not automatically include all files on the classpath as resources unless they
 * are explicitly referenced in a way the compiler can understand Without this runtime
 * hint: The native image might be built without the jwks.json file. When your application
 * tries to load it at runtime, it would likely result in a FileNotFoundException or a
 * similar error, preventing your application from verifying JWTs and thus failing to
 * authenticate users.
 */
public class ApplicationRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		hints.resources().registerPattern("jwks.json");
	}

}
