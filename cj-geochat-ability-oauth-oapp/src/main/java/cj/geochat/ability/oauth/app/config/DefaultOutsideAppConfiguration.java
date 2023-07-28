package cj.geochat.ability.oauth.app.config;

import cj.geochat.ability.oauth.app.oauth2.OAuth2AuthorizationOutsideAppConfiguration;
import cj.geochat.ability.oauth.app.oauth2.OAuth2AuthorizationOutsideAppConfigurer;
import cj.geochat.ability.oauth.app.properties.DefaultSecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackages = {"cj.geochat.ability.oauth.app"})
@EnableConfigurationProperties(DefaultSecurityProperties.class)
@Configuration
public class DefaultOutsideAppConfiguration {

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationOutsideAppConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationOutsideAppConfigurer.class)
                .opaqueToken(Customizer.withDefaults())
//                .authorizationService(new RestAuthorizationService())
        ;
        http
                .cors(Customizer.withDefaults())
                .csrf(c -> c.disable())
                .sessionManagement(c -> c
                        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                )
                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/messages/**").hasAuthority("SCOPE_message:read")
                                .requestMatchers("/swagger-ui/**","/v3/api-docs/**").permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.NEVER))
        ;
        return http.build();
    }
}
