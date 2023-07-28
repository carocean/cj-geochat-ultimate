package cj.geochat.ability.oauth.server.entrypoint.token;

import cj.geochat.ability.oauth.server.AuthorizationGrantType;
import cj.geochat.ability.oauth.server.SpringAuthorizationServerVersion;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OAuth2AuthorizationGrantAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final AuthorizationGrantType authorizationGrantType;
	private final Authentication appPrincipal;
	private final Map<String, Object> additionalParameters;

	/**
	 * Sub-class constructor.
	 *
	 * @param authorizationGrantType the authorization grant type
	 * @param appPrincipal the authenticated client principal
	 * @param additionalParameters the additional parameters
	 */
	protected OAuth2AuthorizationGrantAuthenticationToken(AuthorizationGrantType authorizationGrantType,
														  Authentication appPrincipal, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		Assert.notNull(appPrincipal, "clientPrincipal cannot be null");
		this.authorizationGrantType = authorizationGrantType;
		this.appPrincipal = appPrincipal;
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ?
						new HashMap<>(additionalParameters) :
						Collections.emptyMap());
	}

	/**
	 * Returns the authorization grant type.
	 *
	 * @return the authorization grant type
	 */
	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	@Override
	public Object getPrincipal() {
		return this.appPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the additional parameters.
	 *
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}
}
