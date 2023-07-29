package cj.geochat.ability.oauth.gateway.service;

import cj.geochat.ability.oauth.gateway.AuthorizationService;
import cj.geochat.ability.oauth.gateway.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.gateway.OAuth2Error;
import cj.geochat.ability.oauth.gateway.AppType;
import cj.geochat.ability.oauth.gateway.principal.DefaultAppAuthentication;
import cj.geochat.ability.oauth.gateway.principal.DefaultAppAuthenticationDetails;
import cj.geochat.ability.oauth.gateway.principal.DefaultAppPrincipal;
import cj.geochat.ability.oauth.gateway.properties.DefaultSecurityProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.f4b6a3.ulid.UlidCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class RestAuthorizationService implements AuthorizationService {
    @Autowired
    RestTemplate restTemplate;
    @Autowired
    DefaultSecurityProperties properties;

    public RestAuthorizationService() {
    }

    public RestAuthorizationService(RestTemplate restTemplate, DefaultSecurityProperties properties) {
        this.restTemplate = restTemplate;
        this.properties = properties;
    }

    @Override
    public Authentication findByToken(String token, Object details) throws Throwable {
        int index = UlidCreator.getUlid().hashCode() % properties.getConnectCheckTokenUrl().size();
        String url = properties.getConnectCheckTokenUrl().get(index);
        MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();
        formData.add("token", token);
        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        HttpEntity request1 = new HttpEntity<>(formData, headers);

        ResponseEntity<String> jsonObjectResponseEntity = restTemplate.postForEntity(url, request1, String.class);
        String json = jsonObjectResponseEntity.getBody();
        Map<String, Object> obj = new ObjectMapper().readValue(json, HashMap.class);
        if (!"2038".equals(obj.get("code"))) {
            OAuth2Error error = new OAuth2Error((String) obj.get("code"), (String) obj.get("message"), null);
            throw new OAuth2AuthenticationException(error);
        }
        obj = (Map<String, Object>) obj.get("data");
        DefaultAppPrincipal principal = new DefaultAppPrincipal((String) obj.get("principal_name"), (String) obj.get("app_id"));
        principal.setEnabled((Boolean) obj.get("principal_is_enabled"));
        principal.setEnabled((Boolean) obj.get("principal_is_account_non_expired"));
        principal.setEnabled((Boolean) obj.get("principal_is_account_non_locked"));
        principal.setEnabled((Boolean) obj.get("principal_is_credentials_non_expired"));
        DefaultAppAuthenticationDetails appDetails = new DefaultAppAuthenticationDetails(AppType.outsideApp, details);
        String authoritiesSrc = (String) obj.get("authorities");
        String[] authorArr = authoritiesSrc.split(",");
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(authorArr).map(e ->
                new SimpleGrantedAuthority(e)
        ).collect(Collectors.toSet());
        var authentication = new DefaultAppAuthentication(principal, appDetails, authorities);
        return authentication;
    }
}
