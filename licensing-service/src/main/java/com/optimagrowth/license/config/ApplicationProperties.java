package com.optimagrowth.license.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Application properties.
 */
@Configuration(proxyBeanMethods = false)
@ConfigurationProperties(prefix = "app")
public class ApplicationProperties {

	private String jwks;

	public String getJwks() {
		return jwks;
	}

	public void setJwks(String jwks) {
		this.jwks = jwks;
	}

}
