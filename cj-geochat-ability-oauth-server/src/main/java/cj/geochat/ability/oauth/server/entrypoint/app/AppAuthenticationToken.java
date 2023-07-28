package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.AppAuthenticationMethod;
import cj.geochat.ability.oauth.server.RegisteredApp;
import cj.geochat.ability.oauth.server.SpringAuthorizationServerVersion;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Transient;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Map;

@Transient
public class AppAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final String appId;
	private final RegisteredApp registereApp;
	private final AppAuthenticationMethod appAuthenticationMethod;
	private final Object credentials;
	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided parameters.
	 *
	 * @param appId the client identifier
	 * @param appAuthenticationMethod the authentication method used by the client
	 * @param credentials the client credentials
	 * @param additionalParameters the additional parameters
	 */
	public AppAuthenticationToken(String appId, AppAuthenticationMethod appAuthenticationMethod,
								  @Nullable Object credentials, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(appId, "clientId cannot be empty");
		Assert.notNull(appAuthenticationMethod, "clientAuthenticationMethod cannot be null");
		this.appId = appId;
		this.registereApp = null;
		this.appAuthenticationMethod = appAuthenticationMethod;
		this.credentials = credentials;
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ? additionalParameters : Collections.emptyMap());
	}

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided parameters.
	 *
	 * @param registeredApp the authenticated registered client
	 * @param appAuthenticationMethod the authentication method used by the client
	 * @param credentials the client credentials
	 */
	public AppAuthenticationToken(RegisteredApp registeredApp, AppAuthenticationMethod appAuthenticationMethod,
								  @Nullable Object credentials) {
		super(Collections.emptyList());
		Assert.notNull(registeredApp, "registeredClient cannot be null");
		Assert.notNull(appAuthenticationMethod, "clientAuthenticationMethod cannot be null");
		this.appId = registeredApp.getAppId();
		this.registereApp = registeredApp;
		this.appAuthenticationMethod = appAuthenticationMethod;
		this.credentials = credentials;
		this.additionalParameters = Collections.unmodifiableMap(Collections.emptyMap());
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.appId;
	}

	@Nullable
	@Override
	public Object getCredentials() {
		return this.credentials;
	}


	@Nullable
	public RegisteredApp getRegisteredApp() {
		return this.registereApp;
	}

	public AppAuthenticationMethod getAppAuthenticationMethod() {
		return this.appAuthenticationMethod;
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
