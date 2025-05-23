package com.optimagrowth.license.config;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean
    @LoadBalanced
    RestClient.Builder restClientBuilder() {
        return RestClient.builder();
    }

    @Bean
    public RestClient restClientOAuth(OAuth2AuthorizedClientManager authorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor requestInterceptor = new OAuth2ClientHttpRequestInterceptor(
                authorizedClientManager);
        requestInterceptor.setClientRegistrationIdResolver(clientRegistrationIdResolver());
        return RestClient.builder().requestInterceptor(requestInterceptor).build();
    }

    @Bean
    public RestClient restClientOAuthIdentityProvider(@LoadBalanced RestClient.Builder restClientBuilder,
                                                      OAuth2AuthorizedClientManager authorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor requestInterceptor = new OAuth2ClientHttpRequestInterceptor(
                authorizedClientManager);
        requestInterceptor.setClientRegistrationIdResolver(request -> "keycloak");
        return restClientBuilder.requestInterceptor(requestInterceptor).build();
    }

    private static OAuth2ClientHttpRequestInterceptor.ClientRegistrationIdResolver clientRegistrationIdResolver() {
        return (request) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof JwtAuthenticationToken oauthToken) {
                Jwt jwt = oauthToken.getToken();
                String clientId = jwt.getClaimAsString("client_id");

                System.out.printf(
                        "=======================================\ngetAuthorizedClientRegistrationId " + "%s %s %s = ",
                        oauthToken.getToken().getTokenValue(), oauthToken.getPrincipal(), clientId);
            }
            return (authentication instanceof JwtAuthenticationToken principal) ? principal.getName() : null;
        };
    }

    @Bean
    public OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository, JWKSet jwks) {

        // OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
        // accessTokenResponseClient =
        // refreshTokenTokenResponseClient(
        // jwks);
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

}
