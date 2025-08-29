package com.outlet.oauth2client.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Web security configuration.
 */
@Configuration
public class WebSecurityConfiguration {

	@Autowired
	private CrossDomainAuthenticationSuccessHandler crossDomainAuthenticationSuccessHandler;

	/**
	 * Gets the JWKS for encryption/decryption and signing/verification.
	 * @param resourceLoader the resource loader
	 * @param applicationProperties the application properties
	 * @return the JWKS
	 * @throws IOException the exception
	 * @throws ParseException the exception
	 */
	@Bean
	JWKSet jwks(ResourceLoader resourceLoader, ApplicationProperties applicationProperties)
			throws IOException, ParseException {
		try (InputStream inputStream = resourceLoader.getResource(applicationProperties.getJwks()).getInputStream()) {
			return JWKSet.load(inputStream);
		}
	}

	/**
	 * Referer header is set: When the user is redirected to the login page/provider,
	 * their browser typically sends a Referer header in the subsequent request to the
	 * login page. This Referer header contains the original URL they were trying to
	 * access (e.g., /dashboard). After Spring Security processes the OAuth2 callback and
	 * successfully authenticates the user, this successHandler is invoked. Because
	 * setUseReferer(true) is set, it checks the Referer header of the original request
	 * that led to the authentication process. Referer header is present and valid, the
	 * user will be redirected back to the URL they were originally trying to access
	 * (e.g., /dashboard).
	 * @return
	 */
	@Bean
	public AuthenticationSuccessHandler successHandler() {
		SimpleUrlAuthenticationSuccessHandler handler = new SimpleUrlAuthenticationSuccessHandler();
		handler.setUseReferer(false);
		handler.setDefaultTargetUrl("/token"); // Fallback URL
		return handler;
	}

	// @Autowired
	// private TokenExpirationFilter refreshTokenValidationFilter;

	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

	/**
	 * Configure the security filter chain.
	 * @param http the http security
	 * @param jwks the JWKS
	 * @param clientRegistrationRepository the client registration repository
	 * @return the security filter chain
	 * @throws Exception the exception
	 */
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, JWKSet jwks,
			ClientRegistrationRepository clientRegistrationRepository) throws Exception {
		System.out.println("securityFilterChain");
		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = accessTokenResponseClient(jwks);

		return http
			.authorizeHttpRequests(
					authorizeHttpRequests -> authorizeHttpRequests
						.requestMatchers(new AntPathRequestMatcher("/oauth2/jwks"),
								new AntPathRequestMatcher("/sso" + "-logout/**"))
						.anonymous())
			.authorizeHttpRequests(
					authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(new AntPathRequestMatcher("/**"))
						.authenticated())
			.oauth2Login(oauth2Login -> oauth2Login
				.tokenEndpoint(new Customizer<OAuth2LoginConfigurer<HttpSecurity>.TokenEndpointConfig>() {
					@Override
					public void customize(OAuth2LoginConfigurer<HttpSecurity>.TokenEndpointConfig tokenEndpoint) {
						System.out.println("securityFilterChain -> accessTokenResponseClient");
						tokenEndpoint.accessTokenResponseClient(accessTokenResponseClient);
					}
				})
				.userInfoEndpoint(new Customizer<OAuth2LoginConfigurer<HttpSecurity>.UserInfoEndpointConfig>() {
					@Override
					public void customize(OAuth2LoginConfigurer<HttpSecurity>.UserInfoEndpointConfig userInfoEndpoint) {
						System.out.println("securityFilterChain -> oidcUserService");
						userInfoEndpoint.oidcUserService(oidcUserService());
					}
				})
				// .successHandler(successHandler()))
				.successHandler(crossDomainAuthenticationSuccessHandler))
			// .addFilterAfter(refreshTokenValidationFilter,
			// OAuth2LoginAuthenticationFilter.class)
			.oidcLogout(logout -> logout.backChannel(backChannelLogoutConfigurer -> {
				backChannelLogoutConfigurer.logoutHandler((request, response, authentication) -> {
					System.out.print("--------------------------> Backchannel logout received for user:");
					// Access the logout token
					// OidcLogoutToken logoutToken = authentication.getLogoutToken();
					// Call default behavior
					SecurityContextHolder.clearContext();
					request.getSession(false).invalidate();
				});
			}))
			.logout(logout -> {
				logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository));
				// logout.invalidateHttpSession(true);
				// logout.clearAuthentication(true);
				// logout.deleteCookies("JSESSIONID");
			})
			.with(new DefaultLoginPageConfigurer<>(),
					defaultLoginPage -> defaultLoginPage.withObjectPostProcessor(new ObjectPostProcessor<Object>() {
						@Override
						public <O> O postProcess(O object) {
							if (object instanceof DefaultLoginPageGeneratingFilter filter) {
								// Configure this so the default login page generates the
								// logout message after
								// the post logout redirect
								filter.setLogoutSuccessUrl("/login-user?logout");
							}
							return object;
						}
					}))
			.build();
	}

	/**
	 * Configure the JWT decoder used to decode the ID Token. Creates a JwtDecoder for
	 * each OAuth2 client. This decoder is responsible for validating and parsing JWTs (ID
	 * tokens). It retrieves the necessary cryptographic keys and ensures that JWTs are
	 * properly signed before granting access
	 * @return the jwt decoder factory to decode the ID Token
	 */
	@Bean
	JwtDecoderFactory<ClientRegistration> jwtDecoderFactory() {
		/*
		 * The default implementation is OidcIdTokenDecoderFactory but its customization
		 * is limited.
		 */
		return new JwtDecoderFactory<ClientRegistration>() {
			@Override
			public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
				return jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), key -> {
					System.out.println("jwtDecoderFactory " + clientRegistration.getRegistrationId());
					/*
					 * DefaultJWTProcessor is a core component from Nimbus JOSE + JWT, the
					 * library used to handle JWTs in Spring Security. This processor is
					 * responsible for: Parsing JWTs. Validating their signatures.
					 * Extracting claims like user roles and expiration time.
					 */
					DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
					JWKSource<SecurityContext> jwkSource = jwkSource(clientRegistration);

					// This filters the public keys in the JWKS to select only those used
					// for signing.
					JWSVerificationKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
							JWSAlgorithm.RS256, new JWKSource<SecurityContext>() {
								@Override
								public List<JWK> get(JWKSelector jwkSelector, SecurityContext context)
										throws KeySourceException {
									List<JWK> jwk = jwkSource.get(jwkSelector, context);
									return jwk.stream().filter(new Predicate<JWK>() {
										@Override
										public boolean test(JWK key) {
											System.out.println("jwtDecoderFactory key.getKeyUse() = "
													+ key.getAlgorithm() + " " + key.getKeyID());
											return KeyUse.SIGNATURE.equals(key.getKeyUse());
										}
									}).toList();
								}
							});
					// This tells the JWT processor which key(s) to use when verifying the
					// signature of incoming JWTs
					jwtProcessor.setJWSKeySelector(jwsKeySelector);
					return new NimbusJwtDecoder(jwtProcessor);
				});
			}
		};
	}

	/**
	 * Gets the jwk source to use for a client registration. Fetches the JWKS (public
	 * keys) for a given OAuth2 client from its configured endpoint. These keys are used
	 * to verify the signatures of incoming JWTs. If the URL is invalid, it throws an
	 * exception
	 * @param clientRegistration the client registration
	 * @return the jwk source
	 */
	private JWKSource<SecurityContext> jwkSource(ClientRegistration clientRegistration) {
		String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
		try {
			System.out.println("jwkSource " + jwkSetUri);
			return new RemoteJWKSet<>(new URL(jwkSetUri));
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Gets the oidc frontend logout success handler that calls the OpenID
	 * end_session_endpoint.
	 * @param clientRegistrationRepository clientRegistrationRepository
	 * @return
	 */
	private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
				clientRegistrationRepository);
		// oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/login-user");
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://vegefoods:8090/");
		return (request, response, authentication) -> {
			if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
				String username = oidcUser.getEmail(); // or getName() / getSubject()
				String sessionId = request.getSession(false) != null ? request.getSession(false).getId() : "unknown";
				System.out.println(
						"Logout: cleaning up session for user ------> " + username + " [sessionId=" + sessionId + "]");
			}
			oidcLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
		};
	}

	/**
	 * Gets the access token response client configured for private_key_jwt
	 * authentication. Customizes how access tokens are requested from the authorization
	 * server. It ensures that private_key_jwt authentication is used, where the client
	 * signs the request using a private key. This enhances security compared to
	 * traditional client-secret-based authentication.
	 * @param jwks the JWKS
	 * @return the access token response client
	 */
	private DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient(JWKSet jwks) {
		System.out.println("accessTokenResponseClient() " + jwks.getKeys());
		Function<ClientRegistration, JWK> jwkResolver = clientRegistration -> jwks.getKeys()
			.stream()
			.filter(new Predicate<JWK>() {
				@Override
				public boolean test(JWK jwk) {
					System.out
						.println("accessTokenResponseClient() filter " + jwk.getAlgorithm() + " " + jwk.getKeyID());
					return KeyUse.SIGNATURE.equals(jwk.getKeyUse());
				}
			})
			.findFirst()
			.orElseThrow(() -> new IllegalArgumentException("No signing key available"));

		// responsible for signing authentication requests using the selected key.
		NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> parametersConverter = new NimbusJwtClientAuthenticationParametersConverter<>(
				jwkResolver);
		// convert an OAuth2 authorization request into a properly formatted HTTP request
		var authorizationCodeGrantRequestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
		authorizationCodeGrantRequestEntityConverter.addParametersConverter(parametersConverter);
		var accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		// sending the token request to the OAuth2 provider and retrieving an access token
		// custom converter is set on this client, ensuring every request is signed
		// properly.
		accessTokenResponseClient.setRequestEntityConverter(authorizationCodeGrantRequestEntityConverter);
		return accessTokenResponseClient;
	}

	private static final String AUTHORITY_PREFIX = "";

	/**
	 * Gets the OAuth2UserService that processes the tokens to add the granted
	 * authorities. Processes the authenticated user’s information. It: Loads user details
	 * from the OpenID Connect provider. Extracts roles and permissions from the access
	 * token and ID token. Assigns appropriate authorities (permissions) to the user
	 * @return the oidc user service
	 */
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();
		System.out.println("oidcUserService()");
		final JwtDecoderFactory<ClientRegistration> accessTokenDecoderFactory = new JwtDecoderFactory<ClientRegistration>() {
			@Override
			public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
				System.out.println("oidcUserService.createDecoder getClientId " + clientRegistration.getClientId());
				String issuerUri = clientRegistration.getProviderDetails().getIssuerUri();
				System.out.println("oidcUserService.createDecoder issuerUri " + issuerUri);
				// NimbusJwtDecoder will internally fetch the JSON Web Key Set (JWKS) from
				// the well-known configuration endpoint of the issuer (typically found at
				// issuerUri/.well-known/openid-configuration and then looking
				// for the jwks_uri). The JWKS contains the public keys that the OIDC
				// provider uses to sign its JWTs.
				// The decoder will use these public keys to verify the signature of
				// incoming JWTs.Configures the decoder for signature verification by
				// pointing to the issuer's JWKS endpoint
				NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
				// explicitly sets a validator that checks if the iss (issuer) claim
				// within the decoded JWT matches the expected issuerUri. This confirms
				// that the JWT
				// was indeed issued by the trusted OIDC provider you are expecting
				jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
				return jwtDecoder;
			}
		};

		return new OAuth2UserService<OidcUserRequest, OidcUser>() {
			@Override
			public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
				System.out.println("oidcUserService loadUser ");
				OidcUser oidcUser = delegate.loadUser(userRequest);

				Set<GrantedAuthority> authorities = new HashSet<>();

				System.out.println("oidcUserService createDecoder " + userRequest.getClientRegistration());
				JwtDecoder jwtDecoder = accessTokenDecoderFactory.createDecoder(userRequest.getClientRegistration());
				Jwt jwt = jwtDecoder.decode(userRequest.getAccessToken().getTokenValue());
				OidcIdToken idToken = userRequest.getIdToken();

				System.out
					.println("oidcUserService getAccessToken() = " + userRequest.getAccessToken().getTokenValue());
				System.out.println("oidcUserService getIdToken() = " + idToken.getTokenValue());

				// System.out.println("client.getRefreshToken() = " +
				// client.getRefreshToken().getTokenValue());
				System.out.println("oidcUserService addAuthorities(jwt)");
				addAuthorities(authorities, jwt, "realm_access", AUTHORITY_PREFIX);
				System.out.println("oidcUserService addAuthorities(idToken)");
				addAuthorities(authorities, idToken, "realm_access", AUTHORITY_PREFIX);

				authorities.addAll(oidcUser.getAuthorities());
				System.out.println("oidcUserService.oidcUser " + oidcUser.getIdToken() + "|" + oidcUser.getUserInfo());

				return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
			}
		};
	}

	/**
	 * Add authorities from token. Extracts roles from a JWT claim (e.g., realm_access).
	 * Converts them into Spring Security authorities by adding a prefix (e.g.,
	 * ROLE_ADMIN). Ensures these roles are correctly recognized by the security
	 * framework.
	 * @param authorities to add to
	 * @param token to read from
	 * @param claim to read from that contains the roles
	 * @param authorityPrefix the prefix to prepend to the authority name
	 */
	private void addAuthorities(Set<GrantedAuthority> authorities, ClaimAccessor token, String claim,
			String authorityPrefix) {
		Map<String, Object> realmAccess = token.getClaimAsMap(claim);
		if (realmAccess != null) {
			if (realmAccess.get("roles") instanceof Collection<?> roles) {
				roles.stream().map(value -> {
					System.out.println("authorities = " + authorityPrefix + ":" + value.toString());
					return authorityPrefix + value.toString();
				}).map(SimpleGrantedAuthority::new).forEach(authorities::add);
			}
		}
	}

}
