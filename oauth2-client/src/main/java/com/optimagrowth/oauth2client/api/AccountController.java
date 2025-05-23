package com.optimagrowth.oauth2client.api;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

//import static org.springframework.security.oauth2.client.web.reactive.function.client
// .ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * Account endpoint.
 */
@RestController
public class AccountController {

	private final RestClient webClient;

	public AccountController(@Qualifier("restClientOAuthIdentityProvider") RestClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping(path = "/account", produces = MediaType.APPLICATION_JSON_VALUE)
	public String account(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient,
			@AuthenticationPrincipal OidcUser principal) {
		String issuerUri = authorizedClient.getClientRegistration().getProviderDetails().getIssuerUri();
		String resourceUri = issuerUri + "/account/?userProfileMetadata=true";
		return this.webClient.get()
			.uri(resourceUri)
			.headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
			.accept(MediaType.APPLICATION_JSON)
			// .attributes(oauth2AuthorizedClient(authorizedClient))
			.retrieve()
			.body(String.class);
		// .block();
	}

}
