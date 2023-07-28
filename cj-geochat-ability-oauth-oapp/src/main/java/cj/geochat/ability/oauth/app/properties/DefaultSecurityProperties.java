package cj.geochat.ability.oauth.app.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("spring.security")
@Setter
@Getter
public class DefaultSecurityProperties {
    List<String> connectCheckTokenUrl;
    List<String> whitelist;
    List<String> staticlist;

    public DefaultSecurityProperties() {
        connectCheckTokenUrl = new ArrayList<>();
        whitelist = new ArrayList<>();
        staticlist = new ArrayList<>();
    }
}
