package cj.geochat.ability.oauth.server;

import io.micrometer.common.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * A representation of an OAuth 2.0 "consent" to an Authorization request, which holds state related to the
 * set of {@link #getAuthorities() authorities} granted to a {@link #getRegisteredAppId() client} by the
 * {@link #getPrincipalName() resource owner}.
 * <p>
 * When authorizing access for a given client, the resource owner may only grant a subset of the authorities
 * the client requested. The typical use-case is the {@code authorization_code} flow, in which the client
 * requests a set of {@code scope}s. The resource owner then selects which scopes they grant to the client.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 */
public final class OAuth2AuthorizationConsent implements Serializable {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private static final String AUTHORITIES_SCOPE_PREFIX = "SCOPE_";

	private final String registeredAppId;
	private final String principalName;
	private final Set<GrantedAuthority> authorities;

	private OAuth2AuthorizationConsent(String registeredAppId, String principalName, Set<GrantedAuthority> authorities) {
		this.registeredAppId = registeredAppId;
		this.principalName = principalName;
		this.authorities = Collections.unmodifiableSet(authorities);
	}

	/**
	 * Returns the identifier for the {@link RegisteredApp#getId() registered client}.
	 *
	 * @return the {@link RegisteredApp#getId()}
	 */
	public String getRegisteredAppId() {
		return this.registeredAppId;
	}

	/**
	 * Returns the {@code Principal} name of the resource owner (or client).
	 *
	 * @return the {@code Principal} name of the resource owner (or client)
	 */
	public String getPrincipalName() {
		return this.principalName;
	}

	/**
	 * Returns the {@link GrantedAuthority authorities} granted to the client by the principal.
	 *
	 * @return the {@link GrantedAuthority authorities} granted to the client by the principal.
	 */
	public Set<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	/**
	 * Convenience method for obtaining the {@code scope}s granted to the client by the principal,
	 * extracted from the {@link #getAuthorities() authorities}.
	 *
	 * @return the {@code scope}s granted to the client by the principal.
	 */
	public Set<String> getScopes() {
		Set<String> authorities = new HashSet<>();
		for (GrantedAuthority authority : getAuthorities()) {
			if (authority.getAuthority().startsWith(AUTHORITIES_SCOPE_PREFIX)) {
				authorities.add(authority.getAuthority().replaceFirst(AUTHORITIES_SCOPE_PREFIX, ""));
			}
		}
		return authorities;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OAuth2AuthorizationConsent that = (OAuth2AuthorizationConsent) obj;
		return Objects.equals(this.registeredAppId, that.registeredAppId) &&
				Objects.equals(this.principalName, that.principalName) &&
				Objects.equals(this.authorities, that.authorities);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.registeredAppId, this.principalName, this.authorities);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the values from the provided {@code OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsent the {@code OAuth2AuthorizationConsent} used for initializing the {@link Builder}
	 * @return the {@link Builder}
	 */
	public static Builder from(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		return new Builder(
				authorizationConsent.getRegisteredAppId(),
				authorizationConsent.getPrincipalName(),
				authorizationConsent.getAuthorities()
		);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the given {@link RegisteredApp#getAppId() registeredClientId}
	 * and {@code Principal} name.
	 *
	 * @param registeredAppId the {@link RegisteredApp#getId()}
	 * @param principalName the  {@code Principal} name
	 * @return the {@link Builder}
	 */
	public static Builder withId(@NonNull String registeredAppId, @NonNull String principalName) {
		Assert.hasText(registeredAppId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		return new Builder(registeredAppId, principalName);
	}


	/**
	 * A builder for {@link OAuth2AuthorizationConsent}.
	 */
	public static final class Builder implements Serializable {
		private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

		private final String registeredAppId;
		private final String principalName;
		private final Set<GrantedAuthority> authorities = new HashSet<>();

		private Builder(String registeredAppId, String principalName) {
			this(registeredAppId, principalName, Collections.emptySet());
		}

		private Builder(String registeredAppId, String principalName, Set<GrantedAuthority> authorities) {
			this.registeredAppId = registeredAppId;
			this.principalName = principalName;
			if (!CollectionUtils.isEmpty(authorities)) {
				this.authorities.addAll(authorities);
			}
		}

		/**
		 * Adds a scope to the collection of {@code authorities} in the resulting {@link OAuth2AuthorizationConsent},
		 * wrapping it in a {@link SimpleGrantedAuthority}, prefixed by {@code SCOPE_}. For example, a
		 * {@code message.write} scope would be stored as {@code SCOPE_message.write}.
		 *
		 * @param scope the scope
		 * @return the {@code Builder} for further configuration
		 */
		public Builder scope(String scope) {
			authority(new SimpleGrantedAuthority(AUTHORITIES_SCOPE_PREFIX + scope));
			return this;
		}

		/**
		 * Adds a {@link GrantedAuthority} to the collection of {@code authorities} in the
		 * resulting {@link OAuth2AuthorizationConsent}.
		 *
		 * @param authority the {@link GrantedAuthority}
		 * @return the {@code Builder} for further configuration
		 */
		public Builder authority(GrantedAuthority authority) {
			this.authorities.add(authority);
			return this;
		}

		/**
		 * A {@code Consumer} of the {@code authorities}, allowing the ability to add, replace or remove.
		 *
		 * @param authoritiesConsumer a {@code Consumer} of the {@code authorities}
		 * @return the {@code Builder} for further configuration
		 */
		public Builder authorities(Consumer<Set<GrantedAuthority>> authoritiesConsumer) {
			authoritiesConsumer.accept(this.authorities);
			return this;
		}

		/**
		 * Validate the authorities and build the {@link OAuth2AuthorizationConsent}.
		 * There must be at least one {@link GrantedAuthority}.
		 *
		 * @return the {@link OAuth2AuthorizationConsent}
		 */
		public OAuth2AuthorizationConsent build() {
			Assert.notEmpty(this.authorities, "authorities cannot be empty");
			return new OAuth2AuthorizationConsent(this.registeredAppId, this.principalName, this.authorities);
		}
	}
}
