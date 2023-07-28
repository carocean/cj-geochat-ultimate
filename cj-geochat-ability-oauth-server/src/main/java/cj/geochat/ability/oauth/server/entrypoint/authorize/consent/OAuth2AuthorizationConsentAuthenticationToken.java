package cj.geochat.ability.oauth.server.entrypoint.authorize.consent;

import cj.geochat.ability.oauth.server.SpringAuthorizationServerVersion;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.*;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Authorization Consent
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 0.4.0
// * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 */
public class OAuth2AuthorizationConsentAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final String authorizationUri;
	private final String appId;
	private final Authentication principal;
	private final String state;
	private final Set<String> scopes;
	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2AuthorizationConsentAuthenticationToken} using the provided parameters.
	 *
	 * @param authorizationUri the authorization URI
	 * @param appId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param state the state
	 * @param scopes the requested (or authorized) scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2AuthorizationConsentAuthenticationToken(String authorizationUri, String appId, Authentication principal,
			String state, @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
		Assert.hasText(appId, "clientId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(state, "state cannot be empty");
		this.authorizationUri = authorizationUri;
		this.appId = appId;
		this.principal = principal;
		this.state = state;
		this.scopes = Collections.unmodifiableSet(
				scopes != null ?
						new HashSet<>(scopes) :
						Collections.emptySet());
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ?
						new HashMap<>(additionalParameters) :
						Collections.emptyMap());
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the authorization URI.
	 *
	 * @return the authorization URI
	 */
	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	/**
	 * Returns the client identifier.
	 *
	 * @return the client identifier
	 */
	public String getAppId() {
		return this.appId;
	}

	/**
	 * Returns the state.
	 *
	 * @return the state
	 */
	public String getState() {
		return this.state;
	}

	/**
	 * Returns the requested (or authorized) scope(s).
	 *
	 * @return the requested (or authorized) scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the additional parameters.
	 *
	 * @return the additional parameters, or an empty {@code Map} if not available
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
