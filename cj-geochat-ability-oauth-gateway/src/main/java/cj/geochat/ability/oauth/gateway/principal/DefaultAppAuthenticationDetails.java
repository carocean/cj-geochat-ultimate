package cj.geochat.ability.oauth.gateway.principal;

import cj.geochat.ability.oauth.gateway.AppType;

public class DefaultAppAuthenticationDetails {
    AppType appType;
    private Object details;

    public DefaultAppAuthenticationDetails(AppType appType, Object details) {
        this.details = details;
        this.appType = appType;
    }

    public AppType getAppType() {
        return appType;
    }

    public Object getDetails() {
        return details;
    }
}
