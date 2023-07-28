package cj.geochat.ability.oauth.server.generator;

import cj.geochat.ability.oauth.server.OAuth2Authorization;
import cj.geochat.ability.oauth.server.OAuth2Token;
import cj.geochat.ability.oauth.server.OAuth2TokenContext;
import org.springframework.lang.Nullable;

/**
 * Implementations of this interface are responsible for generating an {@link OAuth2Token}
 * using the attributes contained in the {@link OAuth2TokenContext}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2Token
 * @see OAuth2TokenContext
 * @param <T> the type of the OAuth 2.0 Token
 */
@FunctionalInterface
public interface OAuth2TokenGenerator<T extends OAuth2Token> {

	/**
	 * Generate an OAuth 2.0 Token using the attributes contained in the {@link OAuth2TokenContext},
	 * or return {@code null} if the {@link OAuth2TokenContext#getTokenType()} is not supported.
	 *
	 * <p>
	 * If the returned {@link OAuth2Token} has a set of claims, it should implement {@link }
	 * in order for it to be stored with the {@link OAuth2Authorization}.
	 *
	 * @param context the context containing the OAuth 2.0 Token attributes
	 * @return an {@link OAuth2Token} or {@code null} if the {@link OAuth2TokenContext#getTokenType()} is not supported
	 */
	@Nullable
	T generate(OAuth2TokenContext context);

}
