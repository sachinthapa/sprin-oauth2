// package com.optimagrowth.oauth2client.config;
//
// import com.nimbusds.jose.JOSEException;
// import com.nimbusds.jose.JWSAlgorithm;
// import com.nimbusds.jose.JWSHeader;
// import com.nimbusds.jose.JWSSigner;
// import com.nimbusds.jose.crypto.ECDSASigner;
// import com.nimbusds.jose.jwk.ECKey;
// import com.nimbusds.jose.jwk.JWK;
// import com.nimbusds.jose.jwk.JWKSet;
// import com.nimbusds.jwt.JWTClaimsSet;
// import com.nimbusds.jwt.SignedJWT;
// import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.http.RequestEntity;
// import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
// import
// org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
// import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
// import
// org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
// import
// org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
// import
// org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
// import
// org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
// import org.springframework.security.oauth2.client.registration.ClientRegistration;
// import
// org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
// import
// org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
// import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
// import
// org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
// import
// org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
// import org.springframework.util.LinkedMultiValueMap;
// import org.springframework.util.MultiValueMap;
// import org.springframework.web.client.RestClient;
// import org.springframework.web.util.UriComponentsBuilder;
//
// import java.security.interfaces.ECPrivateKey;
// import java.time.Instant;
// import java.util.Date;
// import java.util.UUID;

/**
 * Web client configuration. This configuration creates a WebClient bean that is
 * automatically configured to handle OAuth 2.0 authorized client requests. When you use
 * this WebClient to make requests to protected resources that require OAuth 2.0
 * authentication, the ServletOAuth2AuthorizedClientExchangeFilterFunction will
 * automatically: Determine the appropriate authorized client based on the request context
 * (e.g., the principal making the request). Retrieve an access token for that client
 * using the OAuth2AuthorizedClientManager. Add the access token to the Authorization
 * header of the outgoing request (typically using the Bearer scheme). This simplifies the
 * process of making authenticated requests with WebClient in a Spring Security OAuth 2.0
 * environment. You can then inject this webClient bean into your services and use it to
 * communicate with protected APIs without manually handling token retrieval and header
 * setting
 *
 * @apiNote <a href=
 * "https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorized-clients
 * .html#oauth2-client-web-client">...</a>
 */
// @Configuration
// public class WebClientConfiguration {
// @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
// private String clientId;
//
// @Autowired
// private OAuth2AuthorizedClientService authorizedClientService;
//
// @Bean
// RestClient webClientWithOAuth2AuthorizedClient(OAuth2AuthorizedClientManager
// oAuth2AuthorizedClientManager) {
// OAuth2ClientHttpRequestInterceptor requestInterceptor = new
// OAuth2ClientHttpRequestInterceptor(
// oAuth2AuthorizedClientManager);
// return RestClient.builder().requestInterceptor(requestInterceptor).build();
// }
// @Bean
// RestClient webClientWithDefaultOAuth2AuthorizedClient(OAuth2AuthorizedClientManager
// oAuth2AuthorizedClientManager,
// OAuth2AuthorizedClientRepository authClientRepo) {
// var servletOAuth2AuthorizedClientExchangeFilterFunction = new
// ServletOAuth2AuthorizedClientExchangeFilterFunction(
// oAuth2AuthorizedClientManager);
// servletOAuth2AuthorizedClientExchangeFilterFunction.setDefaultOAuth2AuthorizedClient(true);
// return RestClient.builder()
// .apply(servletOAuth2AuthorizedClientExchangeFilterFunction.oauth2Configuration())
// .build();
// return RestClient.builder()
// .requestInterceptor(requestInterceptor)
// .build();
// }
// }
//
// @Bean
// public OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager(
// ClientRegistrationRepository clientRegistrationRepository,
// OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository, JWKSet jwks) {
//
// OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
// accessTokenResponseClient = refreshTokenTokenResponseClient(
// jwks);
// var provider = OAuth2AuthorizedClientProviderBuilder.builder()
// .authorizationCode()
// // .refreshToken(refreshTokenGrantBuilder -> {
// // refreshTokenGrantBuilder.accessTokenResponseClient(accessTokenResponseClient);
// // })
// .build();
//
// var cm = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository,
// auth2AuthorizedClientRepository);
//
// cm.setAuthorizedClientProvider(provider);
// return cm;
// }
//
// }
