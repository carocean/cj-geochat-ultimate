package cj.geochat.ability.oauth.server;

import org.springframework.util.*;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriUtils;

import java.io.Serializable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;

public final class OAuth2AuthorizationRequest implements Serializable {
    private static final long serialVersionUID = 610L;
    private String authorizationUri;
    private AuthorizationGrantType authorizationGrantType;
    private OAuth2AuthorizationResponseType responseType;
    private String appId;
    private String redirectUri;
    private Set<String> scopes;
    private String state;
    private Map<String, Object> additionalParameters;
    private String authorizationRequestUri;
    private Map<String, Object> attributes;

    private OAuth2AuthorizationRequest() {
    }

    public String getAuthorizationUri() {
        return this.authorizationUri;
    }

    public AuthorizationGrantType getGrantType() {
        return this.authorizationGrantType;
    }

    public OAuth2AuthorizationResponseType getResponseType() {
        return this.responseType;
    }

    public String getAppId() {
        return this.appId;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public String getState() {
        return this.state;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    public <T> T getAttribute(String name) {
        return (T) this.getAttributes().get(name);
    }

    public String getAuthorizationRequestUri() {
        return this.authorizationRequestUri;
    }

    public static Builder authorizationCode() {
        return new Builder(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    public static Builder from(OAuth2AuthorizationRequest authorizationRequest) {
        Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
        return (new Builder(authorizationRequest.getGrantType())).authorizationUri(authorizationRequest.getAuthorizationUri()).clientId(authorizationRequest.getAppId()).redirectUri(authorizationRequest.getRedirectUri()).scopes(authorizationRequest.getScopes()).state(authorizationRequest.getState()).additionalParameters(authorizationRequest.getAdditionalParameters()).attributes(authorizationRequest.getAttributes());
    }

    public static final class Builder {
        private String authorizationUri;
        private AuthorizationGrantType authorizationGrantType;
        private OAuth2AuthorizationResponseType responseType;
        private String appId;
        private String redirectUri;
        private Set<String> scopes;
        private String state;
        private Map<String, Object> additionalParameters = new LinkedHashMap();
        private Consumer<Map<String, Object>> parametersConsumer = (params) -> {
        };
        private Map<String, Object> attributes = new LinkedHashMap();
        private String authorizationRequestUri;
        private Function<UriBuilder, URI> authorizationRequestUriFunction = (builder) -> {
            return builder.build(new Object[0]);
        };
        private final DefaultUriBuilderFactory uriBuilderFactory;

        private Builder(AuthorizationGrantType authorizationGrantType) {
            Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
            this.authorizationGrantType = authorizationGrantType;
            if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
                this.responseType = OAuth2AuthorizationResponseType.CODE;
            }

            this.uriBuilderFactory = new DefaultUriBuilderFactory();
            this.uriBuilderFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.NONE);
        }

        public Builder authorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.appId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String... scope) {
            return scope != null && scope.length > 0 ? this.scopes(new LinkedHashSet(Arrays.asList(scope))) : this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            if (!CollectionUtils.isEmpty(additionalParameters)) {
                this.additionalParameters.putAll(additionalParameters);
            }

            return this;
        }

        public Builder additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer) {
            if (additionalParametersConsumer != null) {
                additionalParametersConsumer.accept(this.additionalParameters);
            }

            return this;
        }

        public Builder parameters(Consumer<Map<String, Object>> parametersConsumer) {
            if (parametersConsumer != null) {
                this.parametersConsumer = parametersConsumer;
            }

            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            if (!CollectionUtils.isEmpty(attributes)) {
                this.attributes.putAll(attributes);
            }

            return this;
        }

        public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
            if (attributesConsumer != null) {
                attributesConsumer.accept(this.attributes);
            }

            return this;
        }

        public Builder authorizationRequestUri(String authorizationRequestUri) {
            this.authorizationRequestUri = authorizationRequestUri;
            return this;
        }

        public Builder authorizationRequestUri(Function<UriBuilder, URI> authorizationRequestUriFunction) {
            if (authorizationRequestUriFunction != null) {
                this.authorizationRequestUriFunction = authorizationRequestUriFunction;
            }

            return this;
        }

        public OAuth2AuthorizationRequest build() {
            Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
            Assert.hasText(this.appId, "clientId cannot be empty");
            OAuth2AuthorizationRequest authorizationRequest = new OAuth2AuthorizationRequest();
            authorizationRequest.authorizationUri = this.authorizationUri;
            authorizationRequest.authorizationGrantType = this.authorizationGrantType;
            authorizationRequest.responseType = this.responseType;
            authorizationRequest.appId = this.appId;
            authorizationRequest.redirectUri = this.redirectUri;
            authorizationRequest.state = this.state;
            authorizationRequest.scopes = Collections.unmodifiableSet((Set)(CollectionUtils.isEmpty(this.scopes) ? Collections.emptySet() : new LinkedHashSet(this.scopes)));
            authorizationRequest.additionalParameters = Collections.unmodifiableMap(this.additionalParameters);
            authorizationRequest.attributes = Collections.unmodifiableMap(this.attributes);
            authorizationRequest.authorizationRequestUri = StringUtils.hasText(this.authorizationRequestUri) ? this.authorizationRequestUri : this.buildAuthorizationRequestUri();
            return authorizationRequest;
        }

        private String buildAuthorizationRequestUri() {
            Map<String, Object> parameters = this.getParameters();
            this.parametersConsumer.accept(parameters);
            MultiValueMap<String, String> queryParams = new LinkedMultiValueMap();
            parameters.forEach((k, v) -> {
                queryParams.set(encodeQueryParam(k), encodeQueryParam(String.valueOf(v)));
            });
            UriBuilder uriBuilder = this.uriBuilderFactory.uriString(this.authorizationUri).queryParams(queryParams);
            return ((URI)this.authorizationRequestUriFunction.apply(uriBuilder)).toString();
        }

        private Map<String, Object> getParameters() {
            Map<String, Object> parameters = new LinkedHashMap();
            parameters.put("response_type", this.responseType.getValue());
            parameters.put("app_id", this.appId);
            if (!CollectionUtils.isEmpty(this.scopes)) {
                parameters.put("scope", StringUtils.collectionToDelimitedString(this.scopes, " "));
            }

            if (this.state != null) {
                parameters.put("state", this.state);
            }

            if (this.redirectUri != null) {
                parameters.put("redirect_uri", this.redirectUri);
            }

            parameters.putAll(this.additionalParameters);
            return parameters;
        }

        private static String encodeQueryParam(String value) {
            return UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
        }
    }
}