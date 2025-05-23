package com.optimagrowth.oauth2client.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Configuration
public class RestClientConfig {

	@Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
	private String clientId;

	@Bean
	@LoadBalanced
	RestClient.Builder restClientBuilder() {
		return RestClient.builder();
	}

	@Bean
	public RestClient restClientOAuthIdentityProvider(@LoadBalanced RestClient.Builder restClientBuilder,
			OAuth2AuthorizedClientManager authorizedClientManager) {
		OAuth2ClientHttpRequestInterceptor requestInterceptor = new OAuth2ClientHttpRequestInterceptor(
				authorizedClientManager);
		requestInterceptor.setClientRegistrationIdResolver(request -> "keycloak");
		return restClientBuilder.requestInterceptor(requestInterceptor).build();
	}

	@Bean
	public OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository, JWKSet jwks) {

		// OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
		// accessTokenResponseClient =
		// refreshTokenTokenResponseClient(jwks);

		var provider = OAuth2AuthorizedClientProviderBuilder.builder()
			.clientCredentials()
			// .refreshToken(refreshTokenGrantBuilder -> {
			// refreshTokenGrantBuilder.accessTokenResponseClient(accessTokenResponseClient);
			// })
			.build();

		var cm = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository,
				auth2AuthorizedClientRepository);

		cm.setAuthorizedClientProvider(provider);
		return cm;
	}

	// todo why token refreshes on every call when access/refresh token expiry is short
	// todo and when expiry time is close
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient(
			JWKSet jwks) {
		var responseClient = new DefaultRefreshTokenTokenResponseClient();
		responseClient.setRequestEntityConverter(new PrivateKeyJwtRefreshTokenRequestEntityConverter(jwks));
		return responseClient;
	}

	private class PrivateKeyJwtRefreshTokenRequestEntityConverter
			extends OAuth2RefreshTokenGrantRequestEntityConverter {

		private ECPrivateKey cachedPrivateKey;

		private final JWKSet jwks;

		public PrivateKeyJwtRefreshTokenRequestEntityConverter(JWKSet jwks) {
			this.jwks = jwks;
		}

		@Override
		public RequestEntity<?> convert(OAuth2RefreshTokenGrantRequest refreshTokenRequest) {
			ClientRegistration clientRegistration = refreshTokenRequest.getClientRegistration();

			// Only apply to private_key_jwt clients
			if (!ClientAuthenticationMethod.PRIVATE_KEY_JWT.toString()
				.equals(clientRegistration.getClientAuthenticationMethod().toString())) {
				return super.convert(refreshTokenRequest);
			}

			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.add("grant_type", "refresh_token");
			parameters.add("refresh_token", refreshTokenRequest.getRefreshToken().getTokenValue());
			String tokenEndpointUri = clientRegistration.getProviderDetails().getTokenUri();
			String clientAssertion = createClientAssertion(tokenEndpointUri);
			parameters.add("client_id", clientId);

			parameters.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
			parameters.add("client_assertion", clientAssertion);

			System.out.println("""
					===============================>
					PrivateKeyJwtRefreshTokenRequestEntityConverter Token Refreshed
					 ====================================>""");

			return RequestEntity.post(UriComponentsBuilder.fromUriString(tokenEndpointUri).build().toUri())
				.header("Content-Type", "application/x-www-form-urlencoded")
				.body(parameters);
		}

		private String createClientAssertion(String tokenEndpointUri) {
			try {
				JWSSigner signer = new ECDSASigner(loadPrivateKey(jwks));
				JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(clientId)
					.issuer(clientId)
					.audience(tokenEndpointUri)
					.jwtID(UUID.randomUUID().toString())
					.issueTime(new Date())
					.expirationTime(Date.from(Instant.now().plusSeconds(60)))
					.build();

				SignedJWT signedJWT = new SignedJWT(
						new JWSHeader.Builder(JWSAlgorithm.ES512).keyID("cd3cee8c-0bc3-4151-b94e-18a5bc3c71e1").build(),
						claimsSet);

				signedJWT.sign(signer);
				return signedJWT.serialize();
			}
			catch (JOSEException e) {
				throw new RuntimeException("Error creating client assertion JWT", e);
			}
		}

		private ECPrivateKey loadPrivateKey(JWKSet jwks) {
			JWK jwk = jwks.getKeyByKeyId("cd3cee8c-0bc3-4151-b94e-18a5bc3c71e1");
			try {
				ECKey ecKey = (ECKey) jwk;
				if (jwk == null) {
					throw new RuntimeException("EC Key with kid  not found in JWKS");
				}
				// SECURITY WARNING: This assumes your JWKS endpoint contains private key
				// data (the 'd' component)
				// This is unusual and generally not recommended for production systems
				if (ecKey.getD() == null) {
					throw new RuntimeException("EC Key does not contain private key component (d)");
				}
				cachedPrivateKey = ecKey.toECPrivateKey();
				return cachedPrivateKey;
			}
			catch (JOSEException e) {
				throw new RuntimeException(e);
			}
		}

	}

}