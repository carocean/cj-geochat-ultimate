package cj.geochat.ability.oauth.app.service;

import cj.geochat.ability.oauth.app.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.app.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.app.AppType;
import cj.geochat.ability.oauth.app.OAuth2Error;
import cj.geochat.ability.oauth.app.principal.DefaultAppAuthentication;
import cj.geochat.ability.oauth.app.principal.DefaultAppAuthenticationDetails;
import cj.geochat.ability.oauth.app.principal.DefaultAppPrincipal;
import cj.geochat.ability.oauth.app.properties.DefaultSecurityProperties;
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

import java.util.*;
import java.util.stream.Collectors;

@Service
public class RestAuthorizationService implements OAuth2AuthorizationService {
    @Autowired
    RestTemplate restTemplate;
    @Autowired
    DefaultSecurityProperties properties;

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
        Map<String, Object> userMap = (Map<String, Object>) obj.get("user");
        DefaultAppAuthenticationDetails appDetails = new DefaultAppAuthenticationDetails(AppType.outsideApp, details);
        String authoritiesSrc = (String) obj.get("authorities");
        String[] authorArr = authoritiesSrc.split(",");
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(authorArr).map(e ->
                new SimpleGrantedAuthority(e)
        ).collect(Collectors.toSet());
        DefaultAppPrincipal principal = new DefaultAppPrincipal((String) userMap.get("user"),(String) userMap.get("account"), (String) obj.get("app_id"),authorities);
        principal.setEnabled((Boolean) userMap.get("is_enabled"));
        principal.setAccountNonExpired((Boolean) userMap.get("is_account_non_expired"));
        principal.setAccountNonLocked((Boolean) userMap.get("is_account_non_locked"));
        principal.setCredentialsNonExpire((Boolean) userMap.get("is_credentials_non_expired"));
        var authentication = new DefaultAppAuthentication(principal, appDetails);
        return authentication;
    }
}
