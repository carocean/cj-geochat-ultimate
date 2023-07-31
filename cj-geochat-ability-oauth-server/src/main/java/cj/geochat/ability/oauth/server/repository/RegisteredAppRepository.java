package cj.geochat.ability.oauth.server.repository;

import cj.geochat.ability.oauth.server.RegisteredApp;
import org.springframework.lang.Nullable;

/**
 * A repository for OAuth 2.0 {@link RegisteredApp}(s).
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @see RegisteredApp
 * @since 0.0.1
 */
public interface RegisteredAppRepository {
//
//	/**
//	 * Saves the registered client.
//	 *
//	 * <p>
//	 * IMPORTANT: Sensitive information should be encoded externally from the implementation, e.g. {@link RegisteredApp#getAppSecret()}
//	 *
//	 * @param registeredApp the {@link RegisteredApp}
//	 */
//	void save(RegisteredApp registeredApp);

//	/**
//	 * Returns the registered client identified by the provided {@code id},
//	 * or {@code null} if not found.
//	 *
//	 * @param id the registration identifier
//	 * @return the {@link RegisteredApp} if found, otherwise {@code null}
//	 */
//	@Nullable
//	RegisteredApp findById(String id);

	/**
	 * Returns the registered client identified by the provided {@code clientId},
	 * or {@code null} if not found.
	 *
	 * @param appId the client identifier
	 * @return the {@link RegisteredApp} if found, otherwise {@code null}
	 */
	@Nullable
	RegisteredApp findByAppId(String appId);

}
