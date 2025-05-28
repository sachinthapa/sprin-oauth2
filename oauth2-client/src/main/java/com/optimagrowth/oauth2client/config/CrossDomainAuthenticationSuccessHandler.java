package com.optimagrowth.oauth2client.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CrossDomainAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	// Define the external host URL
	private final String externalHostUrl = "http://vegefoods:8090/";

	// Or you could fetch this from configuration properties

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		// You can add logic here to determine the specific path on the external host
		// For example, based on user roles, or original request parameters
		String targetUrl = externalHostUrl; // Default to the main external URL

		// Example: If a parameter 'redirect_to_external' exists, use it (with caution!)
		// String requestedExternalPath = request.getParameter("redirect_to_external");
		// if (requestedExternalPath != null && !requestedExternalPath.isEmpty()) {
		// // WARNING: Validate this path carefully!
		// targetUrl = externalHostUrl + requestedExternalPath;
		// }

		// Perform the redirection to the external host
		response.sendRedirect(targetUrl);

		// Optional: Clear authentication attributes from the session if not needed on
		// this host
		// (This is usually handled by SimpleUrlAuthenticationSuccessHandler's
		// clearAuthenticationAttributes)
		// If you extend SimpleUrlAuthenticationSuccessHandler, call
		// super.clearAuthenticationAttributes(request);
	}

}