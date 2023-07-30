package cj.geochat.ability.oauth.app.principal;

import cj.geochat.ability.oauth.app.AppType;

public class DefaultAppAuthenticationDetails {
    boolean isFromGateway;
    private Object details;

    public DefaultAppAuthenticationDetails(boolean isFromGateway, Object details) {
        this.details = details;
        this.isFromGateway = isFromGateway;
    }

    public boolean isFromGateway() {
        return isFromGateway;
    }

    public Object getDetails() {
        return details;
    }
}
