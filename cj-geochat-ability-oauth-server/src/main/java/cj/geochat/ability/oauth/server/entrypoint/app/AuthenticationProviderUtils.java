package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import org.springframework.security.core.Authentication;

public final class AuthenticationProviderUtils {

	private AuthenticationProviderUtils() {
	}

	static AppAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		AppAuthenticationToken clientPrincipal = null;
		if (AppAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (AppAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	public static <T extends OAuth2Token> OAuth2Authorization invalidate(
			OAuth2Authorization authorization, T token) {

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(token,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

		if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
			authorizationBuilder.token(
					authorization.getAccessToken().getToken(),
					(metadata) ->
							metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

			OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
					authorization.getToken(OAuth2AuthorizationCode.class);
			if (authorizationCode != null && !authorizationCode.isInvalidated()) {
				authorizationBuilder.token(
						authorizationCode.getToken(),
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
			}
		}
		// @formatter:on

		return authorizationBuilder.build();
	}
}
