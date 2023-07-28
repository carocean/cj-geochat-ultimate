package cj.geochat.ability.oauth.server.service;

import cj.geochat.ability.oauth.server.*;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An {@link OAuth2AuthorizationService} that stores {@link OAuth2Authorization}'s in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationService
 */
public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private int maxInitializedAuthorizations = 100;

	/*
	 * Stores "initialized" (uncompleted) authorizations, where an access token has not yet been granted.
	 * This state occurs with the authorization_code grant flow during the user consent step OR
	 * when the code is returned in the authorization response but the access token request is not yet initiated.
	 */
	private Map<String, OAuth2Authorization> initializedAuthorizations =
			Collections.synchronizedMap(new MaxSizeHashMap<>(this.maxInitializedAuthorizations));

	/*
	 * Stores "completed" authorizations, where an access token has been granted.
	 */
	private final Map<String, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

	/*
	 * Constructor used for testing only.
	 */
	InMemoryOAuth2AuthorizationService(int maxInitializedAuthorizations) {
		this.maxInitializedAuthorizations = maxInitializedAuthorizations;
		this.initializedAuthorizations = Collections.synchronizedMap(new MaxSizeHashMap<>(this.maxInitializedAuthorizations));
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService}.
	 */
	public InMemoryOAuth2AuthorizationService() {
		this(Collections.emptyList());
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
	 *
	 * @param authorizations the authorization(s)
	 */
	public InMemoryOAuth2AuthorizationService(OAuth2Authorization... authorizations) {
		this(Arrays.asList(authorizations));
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
	 *
	 * @param authorizations the authorization(s)
	 */
	public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
		Assert.notNull(authorizations, "authorizations cannot be null");
		authorizations.forEach(authorization -> {
			Assert.notNull(authorization, "authorization cannot be null");
			Assert.isTrue(!this.authorizations.containsKey(authorization.getId()),
					"The authorization must be unique. Found duplicate identifier: " + authorization.getId());
			this.authorizations.put(authorization.getId(), authorization);
		});
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		if (isComplete(authorization)) {
			this.authorizations.put(authorization.getId(), authorization);
		} else {
			this.initializedAuthorizations.put(authorization.getId(), authorization);
		}
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		if (isComplete(authorization)) {
			this.authorizations.remove(authorization.getId(), authorization);
		} else {
			this.initializedAuthorizations.remove(authorization.getId(), authorization);
		}
	}

	@Nullable
	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		OAuth2Authorization authorization = this.authorizations.get(id);
		return authorization != null ?
				authorization :
				this.initializedAuthorizations.get(id);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		for (OAuth2Authorization authorization : this.authorizations.values()) {
			if (hasToken(authorization, token, tokenType)) {
				return authorization;
			}
		}
		for (OAuth2Authorization authorization : this.initializedAuthorizations.values()) {
			if (hasToken(authorization, token, tokenType)) {
				return authorization;
			}
		}
		return null;
	}

	private static boolean isComplete(OAuth2Authorization authorization) {
		return authorization.getAccessToken() != null;
	}

	private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
		if (tokenType == null) {
			return matchesState(authorization, token) ||
					matchesAuthorizationCode(authorization, token) ||
					matchesAccessToken(authorization, token) ||
					matchesRefreshToken(authorization, token);
		} else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			return matchesState(authorization, token);
		} else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			return matchesAuthorizationCode(authorization, token);
		} else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return matchesAccessToken(authorization, token);
		} else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			return matchesRefreshToken(authorization, token);
		}
		return false;
	}

	private static boolean matchesState(OAuth2Authorization authorization, String token) {
		return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
	}

	private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
				authorization.getToken(OAuth2AuthorizationCode.class);
		return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
	}

	private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
				authorization.getToken(OAuth2AccessToken.class);
		return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
	}

	private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
				authorization.getToken(OAuth2RefreshToken.class);
		return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
	}

	private static final class MaxSizeHashMap<K, V> extends LinkedHashMap<K, V> {
		private final int maxSize;

		private MaxSizeHashMap(int maxSize) {
			this.maxSize = maxSize;
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
			return size() > this.maxSize;
		}

	}

}
