package cj.geochat.ability.swagger;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("appdoc")
@Getter
@Setter
public class SwaggerProperties {
    Info info;
    SecurityScheme token;
    ExternalDocumentation externalDocs;
}
