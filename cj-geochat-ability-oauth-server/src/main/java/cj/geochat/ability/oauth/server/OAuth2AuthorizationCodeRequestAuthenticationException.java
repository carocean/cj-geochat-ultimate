package cj.geochat.ability.oauth.server;

import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.lang.Nullable;

/**
 * This exception is thrown by {@link OAuth2AuthorizationCodeRequestAuthenticationProvider}
 * when an attempt to authenticate the OAuth 2.0 Authorization Request (or Consent) fails.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 */
public class OAuth2AuthorizationCodeRequestAuthenticationException extends OAuth2AuthenticationException {
	private final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param authorizationCodeRequestAuthentication the {@link } instance of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error error,
			@Nullable OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		super(error);
		this.authorizationCodeRequestAuthentication = authorizationCodeRequestAuthentication;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause the root cause
	 * @param authorizationCodeRequestAuthentication the {@link } instance of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error error, Throwable cause,
			@Nullable OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		super(error, cause);
		this.authorizationCodeRequestAuthentication = authorizationCodeRequestAuthentication;
	}

	/**
	 * Returns the {@link } instance of the OAuth 2.0 Authorization Request (or Consent), or {@code null} if not available.
	 *
	 * @return the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationToken getAuthorizationCodeRequestAuthentication() {
		return this.authorizationCodeRequestAuthentication;
	}

}