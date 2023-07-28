package cj.geochat.ability.oauth.server.service;

import cj.geochat.ability.oauth.server.OAuth2AuthorizationConsent;
import org.springframework.lang.Nullable;

import java.security.Principal;

/**
 * Implementations of this interface are responsible for the management
 * of {@link OAuth2AuthorizationConsent OAuth 2.0 Authorization Consent(s)}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 * @see OAuth2AuthorizationConsent
 */
public interface OAuth2AuthorizationConsentService {

	/**
	 * Saves the {@link OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
	 */
	void save(OAuth2AuthorizationConsent authorizationConsent);

	/**
	 * Removes the {@link OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
	 */
	void remove(OAuth2AuthorizationConsent authorizationConsent);

	/**
	 * Returns the {@link OAuth2AuthorizationConsent} identified by the provided
	 * {@code registeredClientId} and {@code principalName}, or {@code null} if not found.
	 *
	 * @param registeredAppId the identifier for the {@link cj.geochat.security.server.RegisteredApp}
	 * @param principalName the name of the {@link Principal}
	 * @return the {@link OAuth2AuthorizationConsent} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2AuthorizationConsent findById(String registeredAppId, String principalName);

}
