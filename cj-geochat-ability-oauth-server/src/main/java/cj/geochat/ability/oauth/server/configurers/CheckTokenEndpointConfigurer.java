package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.OAuth2ConfigurerUtils;
import cj.geochat.ability.oauth.server.filter.OAuth2CheckTokenEndpointFilter;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

public class CheckTokenEndpointConfigurer extends AbstractHttpConfigurer<CheckTokenEndpointConfigurer, HttpSecurity> {


    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
        var authorizationService=OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
        OAuth2CheckTokenEndpointFilter checkTokenEndpointFilter = new OAuth2CheckTokenEndpointFilter(authorizationService,authorizationServerSettings.getCheckTokenEndpoint());
        httpSecurity.addFilterAfter(postProcess(checkTokenEndpointFilter), AuthorizationFilter.class);
    }

}
