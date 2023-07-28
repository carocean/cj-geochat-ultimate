package cj.geochat.ability.swagger;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("spring.swagger")
public class SwaggerProperties {
    String defaultGroupName;
    String apiVersionPattern;
    private boolean enabled = false;
    int maxVersion=1;
    private String basePackage;
    private ApiInfoProperties apiInfo;
    private List<SwaggerResponseMsg> responseMsg;
    private SwaggerGlobalParameter tokenParameter;
    private List<SwaggerGlobalParameter> parameters=new ArrayList<>();

    public List<SwaggerGlobalParameter> getParameters() {
        return parameters;
    }

    public SwaggerGlobalParameter getTokenParameter() {
        return tokenParameter;
    }

    public void setTokenParameter(SwaggerGlobalParameter tokenParameter) {
        this.tokenParameter = tokenParameter;
    }

    public String getApiVersionPattern() {
        return apiVersionPattern;
    }

    public void setApiVersionPattern(String apiVersionPattern) {
        this.apiVersionPattern = apiVersionPattern;
    }

    public List<SwaggerResponseMsg> getResponseMsg() {
        return responseMsg;
    }

    public void setResponseMsg(List<SwaggerResponseMsg> responseMsg) {
        this.responseMsg = responseMsg;
    }

    public int getMaxVersion() {
        return maxVersion;
    }

    public void setMaxVersion(int maxVersion) {
        this.maxVersion = maxVersion;
    }

    public String getDefaultGroupName() {
        return defaultGroupName;
    }

    public void setDefaultGroupName(String defaultGroupName) {
        this.defaultGroupName = defaultGroupName;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getBasePackage() {
        return basePackage;
    }

    public void setBasePackage(String basePackage) {
        this.basePackage = basePackage;
    }

    public ApiInfoProperties getApiInfo() {
        return apiInfo;
    }

    public void setApiInfo(ApiInfoProperties apiInfo) {
        this.apiInfo = apiInfo;
    }
}
