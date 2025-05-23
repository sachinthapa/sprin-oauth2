package com.optimagrowth.organization.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.net.URL;
import java.util.List;
import java.util.function.Predicate;

/**
 * Web security configuration.
 */
@Configuration
public class WebSecurityConfiguration {

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
	URL jwkSetUri;

	// @Bean
	// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
	// {
	// http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
	// .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())); // Use
	// // default
	// // JWT
	// // processing
	// // Or if you need to explicitly set the jwk-set-uri programmatically:
	// // .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt ->
	// // jwt.jwkSetUri(yourJwkSetUri)));
	// return http.build();
	// }

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.oauth2ResourceServer((oauth2)
		// -> oauth2.jwt(Customizer.withDefaults())
		-> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder()))
		// Use JWT Bearer tokens for authentication
		)
			.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(c -> c.anyRequest().authenticated());
		return http.build();
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return new NimbusJwtDecoder(jwtProcessor());
	}

	private JWTProcessor<SecurityContext> jwtProcessor() {
		DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(jwkSetUri);

		JWSVerificationKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
				JWSAlgorithm.RS256, new JWKSource<SecurityContext>() {
					@Override
					public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
						List<JWK> jwk = jwkSource.get(jwkSelector, context);
						return jwk.stream().filter(new Predicate<JWK>() {
							@Override
							public boolean test(JWK key) {
								System.out.println(
										"jwtDecoderFactory key.getKeyUse() = " + key.getAlgorithm() + key.getKeyID());
								return KeyUse.SIGNATURE.equals(key.getKeyUse());
							}
						}).toList();
					}
				});

		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		return jwtProcessor;
	}

}
