package com.outlet.oauth2client.api;

import com.outlet.oauth2client.config.OAuth2AuthorizedClientProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Login user endpoint.
 */
@RestController
public class LoginUserController {

	@GetMapping(path = "/login-user", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> loginUser(@AuthenticationPrincipal OidcUser principal) {
		return principal.getClaims();
	}

	@GetMapping(path = "/token", produces = MediaType.APPLICATION_JSON_VALUE)
	public String token(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient) {
		String jwtAccessToken = authorizedClient.getAccessToken().getTokenValue();
		String jwtRefrechToken = authorizedClient.getRefreshToken().getTokenValue();
		return "JWT Access Token: \n" + jwtAccessToken + "\n JWT Refresh Token:\n " + jwtRefrechToken;
	}

	@Autowired
	private OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider;

	@GetMapping("/mymethod")
	public String mymethod() {
		return oauth2AuthorizedClientProvider.getClient().getAccessToken().getTokenValue();
	}

	@PostMapping(path = "/sso-logout",
			consumes = { MediaType.APPLICATION_FORM_URLENCODED_VALUE, MediaType.APPLICATION_JSON_VALUE })
	public ResponseEntity<Void> logout(@RequestParam(value = "logout_token", required = false) String logoutTokenParam,
			@RequestBody(required = false) Map<String, String> body) {

		String logoutToken = logoutTokenParam;
		if (logoutToken == null && body != null && body.containsKey("logout_token")) {
			logoutToken = body.get("logout_token");
		}

		System.out.println("==============================> Logout token received: " + logoutToken);
		// Process token validation here

		return ResponseEntity.ok().build();
	}

	@PostMapping(path = "/sso-logout/{registrationId}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<Void> logout(@PathVariable("registrationId") String registrationId,
			@RequestParam(value = "logout_token", required = false) String logoutTokenParam) {
		// Process the logout_token and registrationId
		System.out.println("==============================> Logout token received: " + registrationId);
		return ResponseEntity.ok().build();
	}

}
