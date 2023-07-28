package cj.geochat.ability.oauth.server;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OAuth2TokenContext}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2TokenContext
 */
public final class DefaultOAuth2TokenContext implements OAuth2TokenContext {
	private final Map<Object, Object> context;

	private DefaultOAuth2TokenContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns a new {@link Builder}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link DefaultOAuth2TokenContext}.
	 */
	public static final class Builder extends AbstractBuilder<DefaultOAuth2TokenContext, Builder> {

		private Builder() {
		}

		/**
		 * Builds a new {@link DefaultOAuth2TokenContext}.
		 *
		 * @return the {@link DefaultOAuth2TokenContext}
		 */
		public DefaultOAuth2TokenContext build() {
			return new DefaultOAuth2TokenContext(getContext());
		}

	}

}
