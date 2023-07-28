package cj.geochat.ability.oauth.server;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A context that holds an {@link Authentication} and (optionally) additional information
 * and is used in an {@link AuthenticationProvider}.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see Context
 */
public interface OAuth2AuthenticationContext extends Context {

	/**
	 * Returns the {@link Authentication} associated to the context.
	 *
	 * @param <T> the type of the {@code Authentication}
	 * @return the {@link Authentication}
	 */
	@SuppressWarnings("unchecked")
	default <T extends Authentication> T getAuthentication() {
		return (T) get(Authentication.class);
	}

	/**
	 * A builder for subclasses of {@link OAuth2AuthenticationContext}.
	 *
	 * @param <T> the type of the authentication context
	 * @param <B> the type of the builder
	 * @since 0.2.1
	 */
	abstract class AbstractBuilder<T extends OAuth2AuthenticationContext, B extends AbstractBuilder<T, B>> {
		private final Map<Object, Object> context = new HashMap<>();

		protected AbstractBuilder(Authentication authentication) {
			Assert.notNull(authentication, "authentication cannot be null");
			put(Authentication.class, authentication);
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
			getContext().put(key, value);
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
			contextConsumer.accept(getContext());
			return getThis();
		}

		@SuppressWarnings("unchecked")
		protected <V> V get(Object key) {
			return (V) getContext().get(key);
		}

		protected Map<Object, Object> getContext() {
			return this.context;
		}

		@SuppressWarnings("unchecked")
		protected final B getThis() {
			return (B) this;
		}

		/**
		 * Builds a new {@link OAuth2AuthenticationContext}.
		 *
		 * @return the {@link OAuth2AuthenticationContext}
		 */
		public abstract T build();

	}

}
