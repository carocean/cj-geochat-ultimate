package cj.geochat.ability.elasticsearch.config;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.client.elc.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;

@Configuration
@ComponentScan(basePackages = "cj.geochat.ability.elasticsearch")
@ConditionalOnBean({DefaultElasticSearchClientConfig.class})
public class DefaultElasticsearchConfig {

    @Autowired(required = false)
    DefaultElasticSearchClientConfig defaultElasticSearchClientConfig;

    @SneakyThrows
    @Bean
    ElasticsearchClient elasticsearchClient() {
        return defaultElasticSearchClientConfig.getClientIgnoringCertVerification();
//        return getClientWithCertVerification();
    }

    @Bean
    public ElasticsearchOperations elasticsearchTemplate() {
        return new ElasticsearchTemplate(elasticsearchClient());
    }

//    @SneakyThrows
//    protected RestHighLevelClient getClientWithCertVerification() {
//        //从es服务器中拷贝出来的证书已过期，而且在本地验证证书链不能过。
//        KeyStore keyStore = KeyStoreUtil.createDockerKeyStore("/Users/caroceanjofers/dev-tools/elasticsearch/certs/ca/");
//        SSLContext sslContext = SSLContextBuilder.create().loadKeyMaterial(keyStore, "docker".toCharArray()).build();
//        HttpHeaders compatibilityHeaders = new HttpHeaders();
//        compatibilityHeaders.add("Accept", "application/vnd.elasticsearch+json;compatible-with=7");
//        compatibilityHeaders.add("Content-Type", "application/vnd.elasticsearch+json;"
//                + "compatible-with=7");
//
//        ClientConfiguration clientConfiguration = ClientConfiguration.builder()
//                .connectedTo("localhost:9200")
////                .withProxy("localhost:8080")
//                .usingSsl(sslContext)
//                .withBasicAuth("elastic", "elastic123")
//                .withDefaultHeaders(compatibilityHeaders)    // this variant for imperative code
//                .withHeaders(() -> compatibilityHeaders)     // this variant for reactive code
//                .build();
//
//        RestHighLevelClient client = RestClients.create(clientConfiguration).rest();
//        return client;
//    }


}