package cj.geochat.ability.oauth.server.repository;

import cj.geochat.ability.oauth.server.RegisteredApp;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link RegisteredAppRepository} that stores {@link RegisteredApp}(s) in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation is recommended ONLY to be used during development/testing.
 *
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @see RegisteredAppRepository
 * @see RegisteredApp
 * @since 0.0.1
 */
public final class InMemoryRegisteredAppRepository implements RegisteredAppRepository {
	private final Map<String, RegisteredApp> idRegistrationMap;
	private final Map<String, RegisteredApp> appIdRegistrationMap;

	/**
	 * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryRegisteredAppRepository(RegisteredApp... registrations) {
		this(Arrays.asList(registrations));
	}

	/**
	 * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryRegisteredAppRepository(List<RegisteredApp> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		ConcurrentHashMap<String, RegisteredApp> idRegistrationMapResult = new ConcurrentHashMap<>();
		ConcurrentHashMap<String, RegisteredApp> appIdRegistrationMapResult = new ConcurrentHashMap<>();
		for (RegisteredApp registration : registrations) {
			Assert.notNull(registration, "registration cannot be null");
			assertUniqueIdentifiers(registration, idRegistrationMapResult);
			idRegistrationMapResult.put(registration.getId(), registration);
			appIdRegistrationMapResult.put(registration.getAppId(), registration);
		}
		this.idRegistrationMap = idRegistrationMapResult;
		this.appIdRegistrationMap = appIdRegistrationMapResult;
	}

	@Override
	public void save(RegisteredApp registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		if (!this.idRegistrationMap.containsKey(registeredClient.getId())) {
			assertUniqueIdentifiers(registeredClient, this.idRegistrationMap);
		}
		this.idRegistrationMap.put(registeredClient.getId(), registeredClient);
		this.appIdRegistrationMap.put(registeredClient.getAppId(), registeredClient);
	}

	@Nullable
	@Override
	public RegisteredApp findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.idRegistrationMap.get(id);
	}

	@Nullable
	@Override
	public RegisteredApp findByAppId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return this.appIdRegistrationMap.get(clientId);
	}

	private void assertUniqueIdentifiers(RegisteredApp registeredClient, Map<String, RegisteredApp> registrations) {
		registrations.values().forEach(registration -> {
			if (registeredClient.getId().equals(registration.getId())) {
				throw new IllegalArgumentException("Registered client must be unique. " +
						"Found duplicate identifier: " + registeredClient.getId());
			}
			if (registeredClient.getAppId().equals(registration.getAppId())) {
				throw new IllegalArgumentException("Registered client must be unique. " +
						"Found duplicate client identifier: " + registeredClient.getAppId());
			}
			if (StringUtils.hasText(registeredClient.getAppSecret()) &&
					registeredClient.getAppSecret().equals(registration.getAppSecret())) {
				throw new IllegalArgumentException("Registered client must be unique. " +
						"Found duplicate client secret for identifier: " + registeredClient.getId());
			}
		});
	}

}
