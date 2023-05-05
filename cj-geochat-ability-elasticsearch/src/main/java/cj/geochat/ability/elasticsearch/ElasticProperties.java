package cj.geochat.ability.elasticsearch;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties("spring.elasticsearch")
public class ElasticProperties {
    List<String> uris;
    String username;
    String password;
    int connectionTimeout;
    String pathPrefix;
    int socketTimeout;
    @Value("${spring.data.elasticsearch.repositories.enabled:false}")
    boolean springDataElasticsearchRepositoriesEnabled;
}
