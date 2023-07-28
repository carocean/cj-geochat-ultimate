package cj.geochat.ability.oauth.server;

import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * A context that holds information (to be) associated to an OAuth 2.0 Token
 * and is used by an {@link OAuth2TokenGenerator} and {@link OAuth2TokenCustomizer}.
 *
 * @author Joe Grandja
 * @since 0.1.0
 * @see Context
 * @see OAuth2TokenGenerator
 * @see OAuth2TokenCustomizer
 */
public interface OAuth2TokenContext extends Context {

	/**
	 * Returns the {@link RegisteredApp registered client}.
	 *
	 * @return the {@link RegisteredApp}
	 */
	default RegisteredApp getRegisteredApp() {
		return get(RegisteredApp.class);
	}

	/**
	 * Returns the {@link Authentication} representing the {@code Principal} resource owner (or client).
	 *
	 * @param <T> the type of the {@code Authentication}
	 * @return the {@link Authentication} representing the {@code Principal} resource owner (or client)
	 */
	default <T extends Authentication> T getPrincipal() {
		return get(AbstractBuilder.PRINCIPAL_AUTHENTICATION_KEY);
	}

	/**
	 * Returns the {@link AuthorizationServerContext authorization server context}.
	 *
	 * @return the {@link AuthorizationServerContext}
	 * @since 0.2.3
	 */
	default AuthorizationServerContext getAuthorizationServerContext() {
		return get(AuthorizationServerContext.class);
	}

	/**
	 * Returns the {@link OAuth2Authorization authorization}.
	 *
	 * @return the {@link OAuth2Authorization}, or {@code null} if not available
	 */
	@Nullable
	default OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	/**
	 * Returns the authorized scope(s).
	 *
	 * @return the authorized scope(s)
	 */
	default Set<String> getAuthorizedScopes() {
		return hasKey(AbstractBuilder.AUTHORIZED_SCOPE_KEY) ?
				get(AbstractBuilder.AUTHORIZED_SCOPE_KEY) :
				Collections.emptySet();
	}

	/**
	 * Returns the {@link OAuth2TokenType token type}.
	 *
	 * @return the {@link OAuth2TokenType}
	 */
	default OAuth2TokenType getTokenType() {
		return get(OAuth2TokenType.class);
	}

	/**
	 * Returns the {@link AuthorizationGrantType authorization grant type}.
	 *
	 * @return the {@link AuthorizationGrantType}
	 */
	default AuthorizationGrantType getAuthorizationGrantType() {
		return get(AuthorizationGrantType.class);
	}

	/**
	 * Returns the {@link Authentication} representing the authorization grant.
	 *
	 * @param <T> the type of the {@code Authentication}
	 * @return the {@link Authentication} representing the authorization grant
	 */
	default <T extends Authentication> T getAuthorizationGrant() {
		return get(AbstractBuilder.AUTHORIZATION_GRANT_AUTHENTICATION_KEY);
	}

	/**
	 * Base builder for implementations of {@link OAuth2TokenContext}.
	 *
	 * @param <T> the type of the context
	 * @param <B> the type of the builder
	 */
	abstract class AbstractBuilder<T extends OAuth2TokenContext, B extends AbstractBuilder<T, B>> {
		private static final String PRINCIPAL_AUTHENTICATION_KEY =
				Authentication.class.getName().concat(".PRINCIPAL");
		private static final String AUTHORIZED_SCOPE_KEY =
				OAuth2Authorization.class.getName().concat(".AUTHORIZED_SCOPE");
		private static final String AUTHORIZATION_GRANT_AUTHENTICATION_KEY =
				Authentication.class.getName().concat(".AUTHORIZATION_GRANT");
		private final Map<Object, Object> context = new HashMap<>();

		/**
		 * Sets the {@link RegisteredApp registered client}.
		 *
		 * @param registeredClient the {@link RegisteredApp}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B registeredClient(RegisteredApp registeredClient) {
			return put(RegisteredApp.class, registeredClient);
		}

		/**
		 * Sets the {@link Authentication} representing the {@code Principal} resource owner (or client).
		 *
		 * @param principal the {@link Authentication} representing the {@code Principal} resource owner (or client)
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B principal(Authentication principal) {
			return put(PRINCIPAL_AUTHENTICATION_KEY, principal);
		}

		/**
		 * Sets the {@link AuthorizationServerContext authorization server context}.
		 *
		 * @param authorizationServerContext the {@link AuthorizationServerContext}
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 0.2.3
		 */
		public B authorizationServerContext(AuthorizationServerContext authorizationServerContext) {
			return put(AuthorizationServerContext.class, authorizationServerContext);
		}

		/**
		 * Sets the {@link OAuth2Authorization authorization}.
		 *
		 * @param authorization the {@link OAuth2Authorization}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		/**
		 * Sets the authorized scope(s).
		 *
		 * @param authorizedScopes the authorized scope(s)
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B authorizedScopes(Set<String> authorizedScopes) {
			return put(AUTHORIZED_SCOPE_KEY, authorizedScopes);
		}

		/**
		 * Sets the {@link OAuth2TokenType token type}.
		 *
		 * @param tokenType the {@link OAuth2TokenType}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenType(OAuth2TokenType tokenType) {
			return put(OAuth2TokenType.class, tokenType);
		}

		/**
		 * Sets the {@link AuthorizationGrantType authorization grant type}.
		 *
		 * @param authorizationGrantType the {@link AuthorizationGrantType}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
			return put(AuthorizationGrantType.class, authorizationGrantType);
		}

		/**
		 * Sets the {@link Authentication} representing the authorization grant.
		 *
		 * @param authorizationGrant the {@link Authentication} representing the authorization grant
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B authorizationGrant(Authentication authorizationGrant) {
			return put(AUTHORIZATION_GRANT_AUTHENTICATION_KEY, authorizationGrant);
		}

		/**
		 * Associates an attribute.
		 *
		 * @param key the key for the attribute
		 * @param value the value of the attribute
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B put(Object key, Object value) {
			Assert.notNull(key, "key cannot be null");
			Assert.notNull(value, "value cannot be null");
			this.context.put(key, value);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the attributes {@code Map}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param contextConsumer a {@link Consumer} of the attributes {@code Map}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B context(Consumer<Map<Object, Object>> contextConsumer) {
			contextConsumer.accept(this.context);
			return getThis();
		}

		@SuppressWarnings("unchecked")
		protected <V> V get(Object key) {
			return (V) this.context.get(key);
		}

		protected Map<Object, Object> getContext() {
			return this.context;
		}

		@SuppressWarnings("unchecked")
		protected final B getThis() {
			return (B) this;
		}

		/**
		 * Builds a new {@link OAuth2TokenContext}.
		 *
		 * @return the {@link OAuth2TokenContext}
		 */
		public abstract T build();

	}

}
