package cj.geochat.ability.oauth.iapp.oauth2;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class InsideAppAuthorizationConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        return http.build();
    }

    // @formatter:off
    public static void applyDefaultSecurity(HttpSecurity http) throws Exception {
        var context=http.getSharedObject(ApplicationContext.class);
        InsideAppAuthorizationConfigurer authorizationOutsideAppConfigurer =
                new InsideAppAuthorizationConfigurer(context);

        http
//                .securityMatcher(endpointsMatcher)
//                .authorizeHttpRequests(authorize ->
//                        authorize.anyRequest().authenticated()
//                )
//                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationOutsideAppConfigurer);
    }
}
