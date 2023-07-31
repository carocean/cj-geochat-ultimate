package cj.geochat.ability.oauth.server;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * A representation of a client registration with an OAuth 2.0 Authorization Server.
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 * @since 0.0.1
 */
public class RegisteredApp implements Serializable {
    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
    private String id;
    private String appId;
    private Instant appIdIssuedAt;
    private String appSecret;
    private Instant appSecretExpiresAt;
    private String appName;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    //    private Set<String> postLogoutRedirectUris;
    private Set<String> scopes;
    private boolean requireAuthorizationConsent;
    private boolean reuseRefreshTokens;
    private Duration authorizationCodeTimeToLive = Duration.of(5, ChronoUnit.MINUTES);
    private Duration authorizationAccessTokenTimeToLive = Duration.of(1, ChronoUnit.DAYS);
    private Duration authorizationRefreshTokenTimeToLive = Duration.of(1, ChronoUnit.DAYS);

    protected RegisteredApp() {
    }

    /**
     * Returns the identifier for the registration.
     *
     * @return the identifier for the registration
     */
    public String getId() {
        return this.id;
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
     * Returns the time at which the client identifier was issued.
     *
     * @return the time at which the client identifier was issued
     */
    @Nullable
    public Instant getAppIdIssuedAt() {
        return this.appIdIssuedAt;
    }

    /**
     * Returns the client secret or {@code null} if not available.
     *
     * @return the client secret or {@code null} if not available
     */
    @Nullable
    public String getAppSecret() {
        return this.appSecret;
    }

    public boolean isRequireAuthorizationConsent() {
        return requireAuthorizationConsent;
    }

    /**
     * Returns the time at which the client secret expires or {@code null} if it does not expire.
     *
     * @return the time at which the client secret expires or {@code null} if it does not expire
     */
    @Nullable
    public Instant getAppSecretExpiresAt() {
        return this.appSecretExpiresAt;
    }

    /**
     * Returns the client name.
     *
     * @return the client name
     */
    public String getAppName() {
        return this.appName;
    }

    /**
     * Returns the {@link AuthorizationGrantType authorization grant type(s)} that the client may use.
     *
     * @return the {@code Set} of {@link AuthorizationGrantType authorization grant type(s)}
     */
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return this.authorizationGrantTypes;
    }

    /**
     * Returns the redirect URI(s) that the client may use in redirect-based flows.
     *
     * @return the {@code Set} of redirect URI(s)
     */
    public Set<String> getRedirectUris() {
        return this.redirectUris;
    }

//    /**
//     * Returns the post logout redirect URI(s) that the client may use for logout.
//     * The {@code post_logout_redirect_uri} parameter is used by the client when requesting
//     * that the End-User's User Agent be redirected to after a logout has been performed.
//     *
//     * @return the {@code Set} of post logout redirect URI(s)
//     * @since 1.1
//     */
//    public Set<String> getPostLogoutRedirectUris() {
//        return this.postLogoutRedirectUris;
//    }

    /**
     * Returns the scope(s) that the client may use.
     *
     * @return the {@code Set} of scope(s)
     */
    public Set<String> getScopes() {
        return this.scopes;
    }

    public boolean isReuseRefreshTokens() {
        return reuseRefreshTokens;
    }

    public Duration getAuthorizationCodeTimeToLive() {
        return authorizationCodeTimeToLive;
    }

    public Duration getAuthorizationAccessTokenTimeToLive() {
        return authorizationAccessTokenTimeToLive;
    }

    public Duration getAuthorizationRefreshTokenTimeToLive() {
        return authorizationRefreshTokenTimeToLive;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        RegisteredApp that = (RegisteredApp) obj;
        return Objects.equals(this.id, that.id) &&
                Objects.equals(this.appId, that.appId) &&
                Objects.equals(this.appIdIssuedAt, that.appIdIssuedAt) &&
                Objects.equals(this.appSecret, that.appSecret) &&
                Objects.equals(this.appSecretExpiresAt, that.appSecretExpiresAt) &&
                Objects.equals(this.appName, that.appName) &&
                Objects.equals(this.authorizationGrantTypes, that.authorizationGrantTypes) &&
                Objects.equals(this.redirectUris, that.redirectUris) &&
//                Objects.equals(this.postLogoutRedirectUris, that.postLogoutRedirectUris) &&
                Objects.equals(this.requireAuthorizationConsent, that.requireAuthorizationConsent) &&
                Objects.equals(this.reuseRefreshTokens, that.reuseRefreshTokens) &&
                Objects.equals(this.authorizationCodeTimeToLive, that.authorizationCodeTimeToLive) &&
                Objects.equals(this.authorizationAccessTokenTimeToLive, that.authorizationAccessTokenTimeToLive) &&
                Objects.equals(this.authorizationRefreshTokenTimeToLive, that.authorizationRefreshTokenTimeToLive) &&
                Objects.equals(this.scopes, that.scopes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.appId, this.appIdIssuedAt, this.appSecret, this.appSecretExpiresAt,
                this.appName, this.authorizationGrantTypes, this.redirectUris,
                /*this.postLogoutRedirectUris,*/ this.requireAuthorizationConsent, this.reuseRefreshTokens, this.authorizationCodeTimeToLive, this.authorizationAccessTokenTimeToLive, this.authorizationRefreshTokenTimeToLive, this.scopes);
    }

    @Override
    public String toString() {
        return "RegisteredClient {" +
                "id='" + this.id + '\'' +
                ", clientId='" + this.appId + '\'' +
                ", clientName='" + this.appName + '\'' +
                ", authorizationGrantTypes=" + this.authorizationGrantTypes +
                ", redirectUris=" + this.redirectUris +
//                ", postLogoutRedirectUris=" + this.postLogoutRedirectUris +
                ", requireAuthorizationConsent=" + this.requireAuthorizationConsent +
                ", reuseRefreshTokens=" + this.reuseRefreshTokens +
                ", authorizationCodeTimeToLive=" + this.authorizationCodeTimeToLive +
                ", authorizationRefreshTokenTimeToLive=" + this.authorizationRefreshTokenTimeToLive +
                ", scopes=" + this.scopes +
                '}';
    }

    /**
     * Returns a new {@link Builder}, initialized with the provided registration identifier.
     *
     * @param id the identifier for the registration
     * @return the {@link Builder}
     */
    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    /**
     * Returns a new {@link Builder}, initialized with the values from the provided {@link RegisteredApp}.
     *
     * @param registeredApp the {@link RegisteredApp} used for initializing the {@link Builder}
     * @return the {@link Builder}
     */
    public static Builder from(RegisteredApp registeredApp) {
        Assert.notNull(registeredApp, "registeredClient cannot be null");
        return new Builder(registeredApp);
    }

    /**
     * A builder for {@link RegisteredApp}.
     */
    public static class Builder implements Serializable {
        private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
        private String id;
        private String appId;
        private Instant appIdIssuedAt;
        private String appSecret;
        private Instant appSecretExpiresAt;
        private String appName;
        private boolean requireAuthorizationConsent;
        private final Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
        private final Set<String> redirectUris = new HashSet<>();
        //        private final Set<String> postLogoutRedirectUris = new HashSet<>();
        private final Set<String> scopes = new HashSet<>();

        private boolean reuseRefreshTokens;
        private Duration authorizationCodeTimeToLive;
        private Duration authorizationAccessTokenTimeToLive;
        private Duration authorizationRefreshTokenTimeToLive;

        protected Builder(String id) {
            this.id = id;
        }

        protected Builder(RegisteredApp registeredApp) {
            this.id = registeredApp.getId();
            this.appId = registeredApp.getAppId();
            this.appIdIssuedAt = registeredApp.getAppIdIssuedAt();
            this.appSecret = registeredApp.getAppSecret();
            this.appSecretExpiresAt = registeredApp.getAppSecretExpiresAt();
            this.appName = registeredApp.getAppName();
            if (!CollectionUtils.isEmpty(registeredApp.getAuthorizationGrantTypes())) {
                this.authorizationGrantTypes.addAll(registeredApp.getAuthorizationGrantTypes());
            }
            if (!CollectionUtils.isEmpty(registeredApp.getRedirectUris())) {
                this.redirectUris.addAll(registeredApp.getRedirectUris());
            }
//            if (!CollectionUtils.isEmpty(registeredApp.getPostLogoutRedirectUris())) {
//                this.postLogoutRedirectUris.addAll(registeredApp.getPostLogoutRedirectUris());
//            }
            if (!CollectionUtils.isEmpty(registeredApp.getScopes())) {
                this.scopes.addAll(registeredApp.getScopes());
            }
            this.reuseRefreshTokens = registeredApp.isReuseRefreshTokens();
            this.authorizationCodeTimeToLive = registeredApp.getAuthorizationCodeTimeToLive();
            this.authorizationAccessTokenTimeToLive = registeredApp.getAuthorizationAccessTokenTimeToLive();
            this.authorizationRefreshTokenTimeToLive = registeredApp.authorizationRefreshTokenTimeToLive;
        }

        /**
         * Sets the identifier for the registration.
         *
         * @param id the identifier for the registration
         * @return the {@link Builder}
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * Sets the client identifier.
         *
         * @param clientId the client identifier
         * @return the {@link Builder}
         */
        public Builder appId(String clientId) {
            this.appId = clientId;
            return this;
        }

        /**
         * Sets the time at which the client identifier was issued.
         *
         * @param clientIdIssuedAt the time at which the client identifier was issued
         * @return the {@link Builder}
         */
        public Builder appIdIssuedAt(Instant clientIdIssuedAt) {
            this.appIdIssuedAt = clientIdIssuedAt;
            return this;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret
         * @return the {@link Builder}
         */
        public Builder appSecret(String clientSecret) {
            this.appSecret = clientSecret;
            return this;
        }

        /**
         * Sets the time at which the client secret expires or {@code null} if it does not expire.
         *
         * @param clientSecretExpiresAt the time at which the client secret expires or {@code null} if it does not expire
         * @return the {@link Builder}
         */
        public Builder appSecretExpiresAt(Instant clientSecretExpiresAt) {
            this.appSecretExpiresAt = clientSecretExpiresAt;
            return this;
        }

        /**
         * Sets the client name.
         *
         * @param clientName the client name
         * @return the {@link Builder}
         */
        public Builder appName(String clientName) {
            this.appName = clientName;
            return this;
        }


        /**
         * Adds an {@link AuthorizationGrantType authorization grant type} the client may use.
         *
         * @param authorizationGrantType the authorization grant type
         * @return the {@link Builder}
         */
        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link AuthorizationGrantType authorization grant type(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param authorizationGrantTypesConsumer a {@code Consumer} of the authorization grant type(s)
         * @return the {@link Builder}
         */
        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypesConsumer) {
            authorizationGrantTypesConsumer.accept(this.authorizationGrantTypes);
            return this;
        }

        /**
         * Adds a redirect URI the client may use in a redirect-based flow.
         *
         * @param redirectUri the redirect URI
         * @return the {@link Builder}
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUris.add(redirectUri);
            return this;
        }

        /**
         * A {@code Consumer} of the redirect URI(s)
         * allowing the ability to add, replace, or remove.
         *
         * @param redirectUrisConsumer a {@link Consumer} of the redirect URI(s)
         * @return the {@link Builder}
         */
        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer) {
            redirectUrisConsumer.accept(this.redirectUris);
            return this;
        }

//        /**
//         * Adds a post logout redirect URI the client may use for logout.
//         * The {@code post_logout_redirect_uri} parameter is used by the client when requesting
//         * that the End-User's User Agent be redirected to after a logout has been performed.
//         *
//         * @param postLogoutRedirectUri the post logout redirect URI
//         * @return the {@link Builder}
//         * @since 1.1
//         */
//        public Builder postLogoutRedirectUri(String postLogoutRedirectUri) {
//            this.postLogoutRedirectUris.add(postLogoutRedirectUri);
//            return this;
//        }

//        /**
//         * A {@code Consumer} of the post logout redirect URI(s)
//         * allowing the ability to add, replace, or remove.
//         *
//         * @param postLogoutRedirectUrisConsumer a {@link Consumer} of the post logout redirect URI(s)
//         * @return the {@link Builder}
//         * @since 1.1
//         */
//        public Builder postLogoutRedirectUris(Consumer<Set<String>> postLogoutRedirectUrisConsumer) {
//            postLogoutRedirectUrisConsumer.accept(this.postLogoutRedirectUris);
//            return this;
//        }

        /**
         * Adds a scope the client may use.
         *
         * @param scope the scope
         * @return the {@link Builder}
         */
        public Builder scope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        /**
         * A {@code Consumer} of the scope(s)
         * allowing the ability to add, replace, or remove.
         *
         * @param scopesConsumer a {@link Consumer} of the scope(s)
         * @return the {@link Builder}
         */
        public Builder scopes(Consumer<Set<String>> scopesConsumer) {
            scopesConsumer.accept(this.scopes);
            return this;
        }

        public Builder requireAuthorizationConsent(boolean b) {
            this.requireAuthorizationConsent = b;
            return this;
        }

        public Builder reuseRefreshTokens(boolean reuseRefreshTokens) {
            this.reuseRefreshTokens = reuseRefreshTokens;
            return this;
        }

        public Builder authorizationAccessTokenTimeToLive(Duration authorizationAccessTokenTimeToLive) {
            this.authorizationAccessTokenTimeToLive = authorizationAccessTokenTimeToLive;
            return this;
        }

        public Builder authorizationCodeTimeToLive(Duration authorizationCodeTimeToLive) {
            this.authorizationCodeTimeToLive = authorizationCodeTimeToLive;
            return this;
        }

        public Builder authorizationRefreshTokenTimeToLive(Duration authorizationRefreshTokenTimeToLive) {
            this.authorizationRefreshTokenTimeToLive = authorizationRefreshTokenTimeToLive;
            return this;
        }

        /**
         * Builds a new {@link RegisteredApp}.
         *
         * @return a {@link RegisteredApp}
         */
        public RegisteredApp build() {
            Assert.hasText(this.appId, "clientId cannot be empty");
            Assert.notEmpty(this.authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
            if (this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                Assert.notEmpty(this.redirectUris, "redirectUris cannot be empty");
            }
            if (!StringUtils.hasText(this.appName)) {
                this.appName = this.id;
            }

            validateScopes();
            validateRedirectUris();
//            validatePostLogoutRedirectUris();
            return create();
        }

        private RegisteredApp create() {
            RegisteredApp registeredApp = new RegisteredApp();

            registeredApp.id = this.id;
            registeredApp.appId = this.appId;
            registeredApp.appIdIssuedAt = this.appIdIssuedAt;
            registeredApp.appSecret = this.appSecret;
            registeredApp.appSecretExpiresAt = this.appSecretExpiresAt;
            registeredApp.appName = this.appName;
            registeredApp.requireAuthorizationConsent = this.requireAuthorizationConsent;
            registeredApp.authorizationGrantTypes = Collections.unmodifiableSet(
                    new HashSet<>(this.authorizationGrantTypes));
            registeredApp.redirectUris = Collections.unmodifiableSet(
                    new HashSet<>(this.redirectUris));
//            registeredApp.postLogoutRedirectUris = Collections.unmodifiableSet(
//                    new HashSet<>(this.postLogoutRedirectUris));
            registeredApp.scopes = Collections.unmodifiableSet(
                    new HashSet<>(this.scopes));

            return registeredApp;
        }

        private void validateScopes() {
            if (CollectionUtils.isEmpty(this.scopes)) {
                return;
            }

            for (String scope : this.scopes) {
                Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
            }
        }

        private static boolean validateScope(String scope) {
            return scope == null ||
                    scope.chars().allMatch(c -> withinTheRangeOf(c, 0x21, 0x21) ||
                            withinTheRangeOf(c, 0x23, 0x5B) ||
                            withinTheRangeOf(c, 0x5D, 0x7E));
        }

        private static boolean withinTheRangeOf(int c, int min, int max) {
            return c >= min && c <= max;
        }

        private void validateRedirectUris() {
            if (CollectionUtils.isEmpty(this.redirectUris)) {
                return;
            }

            for (String redirectUri : this.redirectUris) {
                Assert.isTrue(validateRedirectUri(redirectUri),
                        "redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
            }
        }
//
//        private void validatePostLogoutRedirectUris() {
//            if (CollectionUtils.isEmpty(this.postLogoutRedirectUris)) {
//                return;
//            }
//
//            for (String postLogoutRedirectUri : this.postLogoutRedirectUris) {
//                Assert.isTrue(validateRedirectUri(postLogoutRedirectUri),
//                        "post_logout_redirect_uri \"" + postLogoutRedirectUri + "\" is not a valid post logout redirect URI or contains fragment");
//            }
//        }

        private static boolean validateRedirectUri(String redirectUri) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                return validRedirectUri.getFragment() == null;
            } catch (URISyntaxException ex) {
                return false;
            }
        }

    }
}
