package cj.geochat.ability.oauth.server.generator;

import cj.geochat.ability.oauth.server.OAuth2Token;
import cj.geochat.ability.oauth.server.OAuth2TokenContext;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class DelegatingOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {
	private final List<OAuth2TokenGenerator<OAuth2Token>> tokenGenerators;

	/**
	 * Constructs a {@code DelegatingOAuth2TokenGenerator} using the provided parameters.
	 *
	 * @param tokenGenerators an array of {@link OAuth2TokenGenerator}(s)
	 */
	@SafeVarargs
	public DelegatingOAuth2TokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token>... tokenGenerators) {
		Assert.notEmpty(tokenGenerators, "tokenGenerators cannot be empty");
		Assert.noNullElements(tokenGenerators, "tokenGenerator cannot be null");
		this.tokenGenerators = Collections.unmodifiableList(asList(tokenGenerators));
	}

	@Nullable
	@Override
	public OAuth2Token generate(OAuth2TokenContext context) {
		for (OAuth2TokenGenerator<OAuth2Token> tokenGenerator : this.tokenGenerators) {
			OAuth2Token token = tokenGenerator.generate(context);
			if (token != null) {
				return token;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private static List<OAuth2TokenGenerator<OAuth2Token>> asList(
			OAuth2TokenGenerator<? extends OAuth2Token>... tokenGenerators) {

		List<OAuth2TokenGenerator<OAuth2Token>> tokenGeneratorList = new ArrayList<>();
		for (OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator : tokenGenerators) {
			tokenGeneratorList.add((OAuth2TokenGenerator<OAuth2Token>) tokenGenerator);
		}
		return tokenGeneratorList;
	}

}