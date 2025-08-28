package com.outlet.oauth2client.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

@Component
public class TokenExpirationFilter extends OncePerRequestFilter {

	/**
	 * [Login] ---> Get ID Token (60m), Access Token (60m), Refresh Token (90d) After 60
	 * minutes [App] ---> Use Refresh Token to get new Access & ID tokens Repeat until [90
	 * Days Later] ---> Refresh Token expires --> Full re-login required
	 **/
	private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

	@Autowired
	TokenExpirationFilter(OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
		this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
	}

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		System.out.println("======================> TokenExpirationFilter.doFilterInternal");
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication instanceof OAuth2AuthenticationToken token) {
			final OAuth2AuthorizedClient client = oAuth2AuthorizedClientRepository
				.loadAuthorizedClient(token.getAuthorizedClientRegistrationId(), authentication, request);
			if (client != null) {
				final OAuth2AccessToken accessToken = client.getAccessToken();
				if (accessToken.getExpiresAt() != null && accessToken.getExpiresAt()
					// .plusSeconds(10)
					.isBefore(Instant.now())) {
					System.out.println("invalidateSession() = accessToken expired");
					invalidateSession(request, response);
				}
			}
			else {
				System.out.println("invalidateSession client = null");
				invalidateSession(request, response);
			}
		}
		filterChain.doFilter(request, response);
	}

	private void invalidateSession(HttpServletRequest request, HttpServletResponse response) throws IOException {
		SecurityContextHolder.getContext().setAuthentication(null);
		SecurityContextHolder.clearContext();
		final HttpSession httpSession = request.getSession();
		if (httpSession != null) {
			System.out
				.println("===============================> \n" + "TokenExpirationFilter.invalidateSession JWT token "
						+ "expired invalid \n ====================================>");
			// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT token expired
			// or invalid");
			httpSession.invalidate();
		}
	}

}