package cj.geochat.ability.oauth.server;

import org.springframework.util.Assert;

import java.io.Serializable;

public final class AppAuthenticationMethod implements Serializable {
    private static final long serialVersionUID = 610L;
    public static final AppAuthenticationMethod APP_SECRET_BASIC = new AppAuthenticationMethod("app_secret_basic");
    public static final AppAuthenticationMethod APP_SECRET_POST = new AppAuthenticationMethod("app_secret_post");
    public static final AppAuthenticationMethod NONE = new AppAuthenticationMethod("none");
    private final String value;

    public AppAuthenticationMethod(String value) {
        Assert.hasText(value, "value cannot be empty");
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj != null && this.getClass() == obj.getClass()) {
            AppAuthenticationMethod that = (AppAuthenticationMethod)obj;
            return this.getValue().equals(that.getValue());
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.getValue().hashCode();
    }
}