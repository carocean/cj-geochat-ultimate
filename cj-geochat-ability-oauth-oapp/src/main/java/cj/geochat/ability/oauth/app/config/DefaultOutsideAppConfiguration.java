package cj.geochat.ability.oauth.app.config;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.app.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.app.ResultCodeTranslator;
import cj.geochat.ability.oauth.app.oauth2.OutsideAppAuthorizationConfiguration;
import cj.geochat.ability.oauth.app.oauth2.OutsideAppAuthorizationConfigurer;
import cj.geochat.ability.oauth.app.properties.DefaultSecurityProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackages = {"cj.geochat.ability.oauth.app"})
@EnableConfigurationProperties(DefaultSecurityProperties.class)
@Configuration
public class DefaultOutsideAppConfiguration {
    @Autowired
    DefaultSecurityProperties properties;

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OutsideAppAuthorizationConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OutsideAppAuthorizationConfigurer.class)
                .opaqueToken(Customizer.withDefaults())
//                .authorizationService(new RestAuthorizationService())
        ;

        List<String> all = permitResource();

        http
                .cors(Customizer.withDefaults())
                .csrf(c -> c.disable())
                .headers(c->c.frameOptions(o->o.disable()))
                .logout(c->c.disable())
                .formLogin(c->c.disable())
                .anonymous(c->c.disable())
                .sessionManagement(c -> c
                        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                )
                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/messages/**").hasAuthority("SCOPE_message:read")
//                                .requestMatchers("/webjars/**").permitAll()
//                                .requestMatchers("/**/*.js", "/**/*.css","/**/*.ico").permitAll()
//                                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/doc.html", "/doc.html**").permitAll()
                                .requestMatchers(all.toArray(new String[0])).permitAll()
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
//                            ResultCode rc = ResultCodeTranslator.translateException(authException);
                            ResultCode rc = ResultCode.UNAUTHORIZED_CLIENT;
                            Map<String, String> map = new HashMap<>();
                            if (authException instanceof OAuth2AuthenticationException e) {
                                map.put("errorCode", e.getError().getErrorCode());
                                map.put("description", e.getError().getDescription());
                            } else {
                                map.put("exception", authException.getMessage());
                            }
                            Object obj = R.of(rc, map);
                            response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
                        }).accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                            ResultCode rc = ResultCode.ACCESS_DENIED;
                            Map<String, String> map = new HashMap<>();
                            map.put("exception", accessDeniedException.getMessage());
                            Object obj = R.of(rc, map);
                            response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
                        })
                )
        ;
        return http.build();
    }

    private List<String> permitResource() {
        List<String> whitelist = properties.getWhitelist();
        List<String> staticlist = properties.getStaticlist();
        List<String> all = new ArrayList<>();
        all.addAll(whitelist);
        all.addAll(staticlist);
        if (!all.contains("/public/v{id:[0-9]+}/**")) {
            all.add("/public/v{id:[0-9]+}/**");
        }
        if (!all.contains("/webjars/**")) {
            all.add("/webjars/**");
        }
        if (!all.contains("/v3/api-docs/**")) {
            all.add("/v3/api-docs/**");
        }
        if (!all.contains("/swagger-ui/**")) {
            all.add("/swagger-ui/**");
        }
        if (!all.contains("/doc.html")) {
            all.add("/doc.html");
        }
        if (!all.contains("/doc.html**")) {
            all.add("/doc.html**");
        }
        return all;
    }
}
