package cj.geochat.ability.oauth.server;

import cj.geochat.ability.oauth.server.generator.DelegatingOAuth2TokenGenerator;
import cj.geochat.ability.oauth.server.generator.OAuth2AccessTokenGenerator;
import cj.geochat.ability.oauth.server.generator.OAuth2RefreshTokenGenerator;
import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import cj.geochat.ability.oauth.server.repository.RegisteredAppRepository;
import cj.geochat.ability.oauth.server.service.*;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Utility methods for the OAuth 2.0 Configurers.
 *
 * @author Joe Grandja
 * @since 0.1.2
 */
public final class OAuth2ConfigurerUtils {

	private OAuth2ConfigurerUtils() {
	}

	public static RegisteredAppRepository getRegisteredClientRepository(HttpSecurity httpSecurity) {
		RegisteredAppRepository registeredClientRepository = httpSecurity.getSharedObject(RegisteredAppRepository.class);
		if (registeredClientRepository == null) {
			registeredClientRepository = getBean(httpSecurity, RegisteredAppRepository.class);
			httpSecurity.setSharedObject(RegisteredAppRepository.class, registeredClientRepository);
		}
		return registeredClientRepository;
	}

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		OAuth2AuthorizationService authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	public static OAuth2AuthorizationConsentService getAuthorizationConsentService(HttpSecurity httpSecurity) {
		OAuth2AuthorizationConsentService authorizationConsentService = httpSecurity.getSharedObject(OAuth2AuthorizationConsentService.class);
		if (authorizationConsentService == null) {
			authorizationConsentService = getOptionalBean(httpSecurity, OAuth2AuthorizationConsentService.class);
			if (authorizationConsentService == null) {
				authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
			}
			httpSecurity.setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
		}
		return authorizationConsentService;
	}

	@SuppressWarnings("unchecked")
	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = httpSecurity.getSharedObject(OAuth2TokenGenerator.class);
		if (tokenGenerator == null) {
			tokenGenerator = getOptionalBean(httpSecurity, OAuth2TokenGenerator.class);
			if (tokenGenerator == null) {
				OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();

				OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
				tokenGenerator = new DelegatingOAuth2TokenGenerator(
						accessTokenGenerator, refreshTokenGenerator);
			}
			httpSecurity.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
		}
		return tokenGenerator;
	}



	public static AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(AuthorizationServerSettings.class);
		if (authorizationServerSettings == null) {
			authorizationServerSettings = getBean(httpSecurity, AuthorizationServerSettings.class);
			httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
		}
		return authorizationServerSettings;
	}

	public static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
		return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
	}

	@SuppressWarnings("unchecked")
	public static <T> T getBean(HttpSecurity httpSecurity, ResolvableType type) {
		ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length == 1) {
			return (T) context.getBean(names[0]);
		}
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		throw new NoSuchBeanDefinitionException(type);
	}

	public static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				httpSecurity.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
					"Expected single matching bean of type '" + type.getName() + "' but found " +
							beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

	@SuppressWarnings("unchecked")
	public static <T> T getOptionalBean(HttpSecurity httpSecurity, ResolvableType type) {
		ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return names.length == 1 ? (T) context.getBean(names[0]) : null;
	}

}
