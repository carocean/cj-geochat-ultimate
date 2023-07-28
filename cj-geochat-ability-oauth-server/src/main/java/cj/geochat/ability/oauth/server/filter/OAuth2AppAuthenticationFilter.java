package cj.geochat.ability.oauth.server.filter;

import cj.geochat.ability.oauth.server.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.server.OAuth2Error;
import cj.geochat.ability.oauth.server.OAuth2ErrorCodes;
import cj.geochat.ability.oauth.server.entrypoint.app.AppSecretBasicAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.app.AppSecretPostAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.app.AppAuthenticationToken;
import cj.geochat.ability.oauth.server.entrypoint.app.PublicAppAuthenticationConverter;
import cj.geochat.ability.oauth.server.convert.DelegatingAuthTypeConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public final class OAuth2AppAuthenticationFilter extends OncePerRequestFilter {
	private final AuthenticationManager authenticationManager;
	private final RequestMatcher requestMatcher;
//	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
			new WebAuthenticationDetailsSource();
	private IAuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::onAuthenticationSuccess;
	private AuthenticationFailureHandler authenticationFailureHandler = this::onAuthenticationFailure;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationFilter} using the provided parameters.
	 *
	 * @param authenticationManager the {@link AuthenticationManager} used for authenticating the client
	 * @param requestMatcher the {@link RequestMatcher} used for matching against the {@code HttpServletRequest}
	 */
	public OAuth2AppAuthenticationFilter(AuthenticationManager authenticationManager,
										 RequestMatcher requestMatcher) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.authenticationManager = authenticationManager;
		this.requestMatcher = requestMatcher;
		this.authenticationConverter = new DelegatingAuthTypeConverter(
				"app_secret_post",
				Arrays.asList(
						new AppSecretBasicAuthenticationConverter(),
						new AppSecretPostAuthenticationConverter(),
						new PublicAppAuthenticationConverter()));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication authenticationRequest = this.authenticationConverter.convert(request);
			if (authenticationRequest instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) authenticationRequest).setDetails(
						this.authenticationDetailsSource.buildDetails(request));
			}
			if (authenticationRequest != null) {
				validateClientIdentifier(authenticationRequest);
				Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
				this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
			}
			filterChain.doFilter(request, response);

		} catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Client authentication failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}


	public void setAuthenticationConverter(IAuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling a failed client authentication
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling a failed client authentication
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Set SecurityContextHolder authentication to %s",
					authentication.getClass().getSimpleName()));
		}
	}

	private void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {

		SecurityContextHolder.clearContext();

		// TODO
		// The authorization server MAY return an HTTP 401 (Unauthorized) status code
		// to indicate which HTTP authentication schemes are supported.
		// If the client attempted to authenticate via the "Authorization" request header field,
		// the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and
		// include the "WWW-Authenticate" response header field
		// matching the authentication scheme used by the client.

		OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
			httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
		} else {
			httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		}
		// We don't want to reveal too much information to the caller so just return the error code
		OAuth2Error errorResponse = new OAuth2Error(error.getErrorCode());
//		this.errorHttpResponseConverter.write(errorResponse, null, httpResponse);
		Map<String, Object> body = new HashMap<>();
		body.put("method", "Error");
		body.put("error", errorResponse);
		response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(body));
	}

	private static void validateClientIdentifier(Authentication authentication) {
		if (!(authentication instanceof AppAuthenticationToken)) {
			return;
		}

		AppAuthenticationToken clientAuthentication = (AppAuthenticationToken) authentication;
		String clientId = (String) clientAuthentication.getPrincipal();
		for (int i = 0; i < clientId.length(); i++) {
			char charAt = clientId.charAt(i);
			if (!(charAt >= 32 && charAt <= 126)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
			}
		}
	}

}