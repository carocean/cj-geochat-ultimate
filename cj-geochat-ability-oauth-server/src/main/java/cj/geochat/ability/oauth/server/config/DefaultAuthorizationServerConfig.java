package cj.geochat.ability.oauth.server.config;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.server.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.server.ResultCodeTranslator;
import cj.geochat.ability.oauth.server.entrypoint.authorize.consent.OAuth2AuthorizationConsentAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.authorize.consent.OAuth2AuthorizationConsentAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.token.OAuth2AuthorizationCodeAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.token.OAuth2AuthorizationCodeAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.token.refresh.OAuth2RefreshTokenAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.token.refresh.OAuth2RefreshTokenAuthenticationProvider;
import cj.geochat.ability.oauth.server.login.method.password.PasswordAuthenticationConverter;
import cj.geochat.ability.oauth.server.login.method.password.PasswordAuthenticationProvider;
import cj.geochat.ability.oauth.server.login.method.sms.SmsCodeAuthenticationConverter;
import cj.geochat.ability.oauth.server.login.method.sms.SmsCodeAuthenticationProvider;
import cj.geochat.ability.oauth.server.oauth2.OAuth2AuthorizationServerConfiguration;
import cj.geochat.ability.oauth.server.oauth2.OAuth2AuthorizationServerConfigurer;
import cj.geochat.ability.oauth.server.properties.DefaultSecurityProperties;
import cj.geochat.ability.oauth.server.service.InMemoryOAuth2AuthorizationConsentService;
import cj.geochat.ability.oauth.server.service.InMemoryOAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.user.details.GeochatUser;
import cj.geochat.ability.oauth.server.util.SecurityBeanUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@EnableWebSecurity
@EnableMethodSecurity
@ComponentScan(basePackages = {"cj.geochat.ability.oauth.server"})
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(DefaultSecurityProperties.class)
public class DefaultAuthorizationServerConfig {
    @Autowired
    DefaultSecurityProperties properties;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        UserDetailsService userDetailsService = SecurityBeanUtil.getBean(http, UserDetailsService.class);
        PasswordEncoder passwordEncoder = SecurityBeanUtil.getBean(http, PasswordEncoder.class);

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .formLogin(c -> c
                        .loginPage("/v1/login")
                        .defaultAuthenticationConverter(PasswordAuthenticationConverter.class)
                        .authenticationConverter(new SmsCodeAuthenticationConverter())
                        .authenticationProvider(new SmsCodeAuthenticationProvider(passwordEncoder, userDetailsService))
                        .authenticationConverter(new PasswordAuthenticationConverter())
                        .authenticationProvider(new PasswordAuthenticationProvider(passwordEncoder, userDetailsService))
                        .failureHandler((request, response, exception) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                            ResultCode rc = ResultCodeTranslator.translateException(exception);
                            Object obj = R.of(rc, exception.getMessage());
                            response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
                        })
                        .successHandler((request, response, authentication) -> {
                            GeochatUser user = (GeochatUser) authentication.getPrincipal();
                            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                            ResultCode rc = ResultCode.IS_AUTHORIZED;
                            Map<String, String> map = new HashMap<>();
                            map.put("user", user.getUsername());
                            map.put("account", user.getAccount());
                            Object obj = R.of(rc, map);
                            response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
                        })
                )
                .oauth2Server(c -> c
//                                .authorizationServerSettings()
//                                .appEndpoint(appAuthenticationConfigurer -> appAuthenticationConfigurer
//                                                .authenticationConverter(null)
//                                                .authenticationProvider(null)
//                                        )
//                                .checkTokenEndpoint(checkTokenEndpointConfigurer -> checkTokenEndpointConfigurer
//                                        .sucessHandler()
//                                        .errorHandler()
//                                )
                                .authorizationEndpoint(endpointConfigurer -> endpointConfigurer
                                                .authenticationConverter(new OAuth2AuthorizationCodeRequestAuthenticationConverter())
                                                .authenticationConverter(new OAuth2AuthorizationConsentAuthenticationConverter())
                                                .authenticationProvider(new OAuth2AuthorizationCodeRequestAuthenticationProvider())
                                                .authenticationProvider(new OAuth2AuthorizationConsentAuthenticationProvider())
//                                .registeredAppRepository(new InMemoryRegisteredAppRepository(Arrays.asList()))
//                                                .authorizationService(new InMemoryOAuth2AuthorizationService())
//                                                .authorizationConsentService(new InMemoryOAuth2AuthorizationConsentService())
                                                .authorizationCodeGenerator(null)
                                )
                                .tokenEndpoint(tokenEndpointConfigurer -> tokenEndpointConfigurer
                                                .authenticationConverter(new OAuth2AuthorizationCodeAuthenticationConverter())
                                                .authenticationConverter(new OAuth2RefreshTokenAuthenticationConverter())
                                                .authenticationProvider(new OAuth2AuthorizationCodeAuthenticationProvider())
                                                .authenticationProvider(new OAuth2RefreshTokenAuthenticationProvider())
//                                        .authorizationCodeGenerator(new DelegatingOAuth2TokenGenerator(new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator()))
                                )
                                .logout(Customizer.withDefaults())
//                                .logout(logoutEndpointConfigurer -> logoutEndpointConfigurer
//                                                .successHandler()
////                                        .failureHandler()
////                                        .logoutService()
//                                )
                )
        ;
        List<String> whitelist = properties.getWhitelist();
        List<String> staticlist = properties.getStaticlist();
        List<String> all = new ArrayList<>();
        all.addAll(whitelist);
        all.addAll(staticlist);
        if (!all.contains("/oauth2/check_token") && !all.contains("/oauth2/v1/check_token")) {
            all.add("/oauth2/check_token");
            all.add("/oauth2/v1/check_token");
        }
        if (!all.contains("/oauth2/logout") && !all.contains("/oauth2/v1/logout")) {
            all.add("/oauth2/logout");
            all.add("/oauth2/v1/logout");
        }
        http
                .cors(Customizer.withDefaults())
                .sessionManagement(c -> c
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                )
                .csrf(c -> c.disable())
                .authorizeHttpRequests(c -> {
                    c.requestMatchers(all.toArray(new String[0]))
                            .permitAll()
                            .anyRequest().authenticated();
                })
                .anonymous(c -> c.disable())
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                            ResultCode rc = ResultCodeTranslator.translateException(authException);
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
                .logout(c -> c.disable())
        ;

        return http.build();
    }

}
