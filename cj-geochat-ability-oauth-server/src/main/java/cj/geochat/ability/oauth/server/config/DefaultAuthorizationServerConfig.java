package cj.geochat.ability.oauth.server.config;

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
import cj.geochat.ability.oauth.server.util.SecurityBeanUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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
                            Map<String, String> map = new HashMap<>();
                            map.put("login error", exception.getMessage());
                            response.getWriter().write(new ObjectMapper().writeValueAsString(map));
                        })
                        .successHandler((request, response, authentication) -> {
                            Map<String, String> map = new HashMap<>();
                            map.put("login success", "aaa");
                            response.getWriter().write(new ObjectMapper().writeValueAsString(map));
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
                                                .authorizationService(new InMemoryOAuth2AuthorizationService())
                                                .authorizationConsentService(new InMemoryOAuth2AuthorizationConsentService())
                                                .authorizationCodeGenerator(null)
                                )
                                .tokenEndpoint(tokenEndpointConfigurer -> tokenEndpointConfigurer
                                                .authenticationConverter(new OAuth2AuthorizationCodeAuthenticationConverter())
                                                .authenticationConverter(new OAuth2RefreshTokenAuthenticationConverter())
                                                .authenticationProvider(new OAuth2AuthorizationCodeAuthenticationProvider())
                                                .authenticationProvider(new OAuth2RefreshTokenAuthenticationProvider())
//                                        .authorizationCodeGenerator(new DelegatingOAuth2TokenGenerator(new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator()))
                                )
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
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            Map<String, String> map = new HashMap<>();
                            map.put("authenticationEntryPoint", authException.getMessage());
                            response.getWriter().write(new ObjectMapper().writeValueAsString(map));
                        }).accessDeniedHandler((request, response, accessDeniedException) -> {
                            Map<String, String> map = new HashMap<>();
                            map.put("denied", accessDeniedException.getMessage());
                            response.getWriter().write(new ObjectMapper().writeValueAsString(map));
                        })
                )
        ;

        return http.build();
    }

}
