package cj.geochat.ability.oauth.server;


import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;

/**
 * A context that holds information of the Authorization Server runtime environment.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerSettings
 * @see AuthorizationServerContextHolder
 */
public interface AuthorizationServerContext {

	/**
	 * Returns the {@code URL} of the Authorization Server's issuer identifier.
	 *
	 * @return the {@code URL} of the Authorization Server's issuer identifier
	 */
	String getIssuer();

	/**
	 * Returns the {@link AuthorizationServerSettings}.
	 *
	 * @return the {@link AuthorizationServerSettings}
	 */
	AuthorizationServerSettings getAuthorizationServerSettings();

}
