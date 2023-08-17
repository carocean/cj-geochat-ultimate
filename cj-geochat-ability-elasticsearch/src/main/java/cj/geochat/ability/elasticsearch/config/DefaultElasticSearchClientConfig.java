package cj.geochat.ability.elasticsearch.config;

import cj.geochat.ability.elasticsearch.ElasticProperties;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.ElasticsearchTransport;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import lombok.SneakyThrows;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.util.List;

@Component
@EnableConfigurationProperties(ElasticProperties.class)
public class DefaultElasticSearchClientConfig {
    @Autowired
    ElasticProperties properties;

    @ConditionalOnProperty(value = "spring.data.elasticsearch.repositories.enabled", havingValue = "true")
    @SneakyThrows
    protected ElasticsearchClient getClientIgnoringCertVerification() {
        //ignoring ssl certificate verification.
        final CredentialsProvider credentialsProvider =
                new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials(properties.getUsername(), properties.getPassword()));

        SSLContextBuilder sslBuilder = SSLContexts.custom()
                .loadTrustMaterial((x509Certificates, s) -> true);
        final SSLContext sslContext = sslBuilder.build();
        List<String> uris = properties.getUris();
        HttpHost[] httpHosts = new HttpHost[uris.size()];
        for (int i = 0; i < uris.size(); i++) {
            String url = uris.get(i);
            httpHosts[i] = HttpHost.create(url);
        }
        Header[] compatibilityHeaders = new Header[2];
        compatibilityHeaders[0] = new BasicHeader("Accept", "application/vnd.elasticsearch+json;compatible-with=7");
        compatibilityHeaders[1] = new BasicHeader("Content-Type", "application/vnd.elasticsearch+json;"
                + "compatible-with=7");
        RestClient restClient = RestClient
                .builder(httpHosts)
                .setDefaultHeaders(compatibilityHeaders)
//port number is given as 443 since its https schema
                .setHttpClientConfigCallback(httpClientBuilder -> httpClientBuilder
                        .setSSLContext(sslContext)
                        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                        .setDefaultCredentialsProvider(credentialsProvider))
                .setRequestConfigCallback(requestConfigBuilder -> requestConfigBuilder.setConnectTimeout(properties.getConnectionTimeout())
                        .setSocketTimeout(properties.getSocketTimeout())).build();
        ElasticsearchTransport transport = new RestClientTransport(restClient, new JacksonJsonpMapper());
        ElasticsearchClient client = new ElasticsearchClient(transport);
        return client;
    }
}
