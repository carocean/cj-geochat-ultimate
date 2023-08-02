package cj.geochat.ability.oauth.server.settings;

import org.springframework.util.Assert;

import java.util.Map;

/**
 * A facility for authorization server configuration settings.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @see AbstractSettings
 * @since 0.1.0
 */
public final class AuthorizationServerSettings extends AbstractSettings {

    private AuthorizationServerSettings(Map<String, Object> settings) {
        super(settings);
    }

    /**
     * Returns the URL of the Authorization Server's Issuer Identifier.
     *
     * @return the URL of the Authorization Server's Issuer Identifier
     */
    public String getIssuer() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.ISSUER);
    }

    /**
     * Returns the OAuth 2.0 Authorization endpoint. The default is {@code /oauth2/authorize}.
     *
     * @return the Authorization endpoint
     */
    public String getAuthorizationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT);
    }


    /**
     * Returns the OAuth 2.0 Token endpoint. The default is {@code /oauth2/token}.
     *
     * @return the Token endpoint
     */
    public String getTokenEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT);
    }

    public String getCheckTokenEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.CHECK_TOKEN_ENDPOINT);
    }
    public String getLogoutEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.LOGOUT_ENDPOINT);
    }

    /**
     * Returns the OAuth 2.0 Token Revocation endpoint. The default is {@code /oauth2/revoke}.
     *
     * @return the Token Revocation endpoint
     */
    public String getTokenRevocationEndpoint() {
        return getSetting(ConfigurationSettingNames.AuthorizationServer.TOKEN_REVOCATION_ENDPOINT);
    }

    /**
     * Constructs a new {@link Builder} with the default settings.
     *
     * @return the {@link Builder}
     */
    public static Builder builder() {
        return new Builder()
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .checkTokenEndpoint("/oauth2/check_token")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .logoutEndpoint("/oauth2/logout")
                ;
    }

    /**
     * Constructs a new {@link Builder} with the provided settings.
     *
     * @param settings the settings to initialize the builder
     * @return the {@link Builder}
     */
    public static Builder withSettings(Map<String, Object> settings) {
        Assert.notEmpty(settings, "settings cannot be empty");
        return new Builder()
                .settings(s -> s.putAll(settings));
    }

    /**
     * A builder for {@link AuthorizationServerSettings}.
     */
    public final static class Builder extends AbstractBuilder<AuthorizationServerSettings, Builder> {

        private Builder() {
        }

        /**
         * Sets the URL the Authorization Server uses as its Issuer Identifier.
         *
         * @param issuer the URL the Authorization Server uses as its Issuer Identifier.
         * @return the {@link Builder} for further configuration
         */
        public Builder issuer(String issuer) {
            return setting(ConfigurationSettingNames.AuthorizationServer.ISSUER, issuer);
        }

        /**
         * Sets the OAuth 2.0 Authorization endpoint.
         *
         * @param authorizationEndpoint the Authorization endpoint
         * @return the {@link Builder} for further configuration
         */
        public Builder authorizationEndpoint(String authorizationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
        }


        /**
         * Sets the OAuth 2.0 Token endpoint.
         *
         * @param tokenEndpoint the Token endpoint
         * @return the {@link Builder} for further configuration
         */
        public Builder tokenEndpoint(String tokenEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_ENDPOINT, tokenEndpoint);
        }

        public Builder tokenRevocationEndpoint(String tokenRevocationEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.TOKEN_REVOCATION_ENDPOINT, tokenRevocationEndpoint);
        }
        public Builder logoutEndpoint(String logoutEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.LOGOUT_ENDPOINT, logoutEndpoint);
        }
        public Builder checkTokenEndpoint(String checkTokenEndpoint) {
            return setting(ConfigurationSettingNames.AuthorizationServer.CHECK_TOKEN_ENDPOINT, checkTokenEndpoint);
        }

        /**
         * Builds the {@link AuthorizationServerSettings}.
         *
         * @return the {@link AuthorizationServerSettings}
         */
        @Override
        public AuthorizationServerSettings build() {
            return new AuthorizationServerSettings(getSettings());
        }

    }

}
