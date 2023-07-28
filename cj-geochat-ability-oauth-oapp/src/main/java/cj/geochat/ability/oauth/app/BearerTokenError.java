package cj.geochat.ability.oauth.app;

import org.springframework.http.HttpStatus;
import org.springframework.util.Assert;

public final class BearerTokenError extends OAuth2Error {
    private final HttpStatus httpStatus;
    private final String scope;

    public BearerTokenError(String errorCode, HttpStatus httpStatus, String description, String errorUri) {
        this(errorCode, httpStatus, description, errorUri, (String)null);
    }

    public BearerTokenError(String errorCode, HttpStatus httpStatus, String description, String errorUri, String scope) {
        super(errorCode, description, errorUri);
        Assert.notNull(httpStatus, "httpStatus cannot be null");
        Assert.isTrue(isDescriptionValid(description), "description contains invalid ASCII characters, it must conform to RFC 6750");
        Assert.isTrue(isErrorCodeValid(errorCode), "errorCode contains invalid ASCII characters, it must conform to RFC 6750");
        Assert.isTrue(isErrorUriValid(errorUri), "errorUri contains invalid ASCII characters, it must conform to RFC 6750");
        Assert.isTrue(isScopeValid(scope), "scope contains invalid ASCII characters, it must conform to RFC 6750");
        this.httpStatus = httpStatus;
        this.scope = scope;
    }

    public HttpStatus getHttpStatus() {
        return this.httpStatus;
    }

    public String getScope() {
        return this.scope;
    }

    private static boolean isDescriptionValid(String description) {
        return description == null || description.chars().allMatch((c) -> {
            return withinTheRangeOf(c, 32, 33) || withinTheRangeOf(c, 35, 91) || withinTheRangeOf(c, 93, 126);
        });
    }

    private static boolean isErrorCodeValid(String errorCode) {
        return errorCode.chars().allMatch((c) -> {
            return withinTheRangeOf(c, 32, 33) || withinTheRangeOf(c, 35, 91) || withinTheRangeOf(c, 93, 126);
        });
    }

    private static boolean isErrorUriValid(String errorUri) {
        return errorUri == null || errorUri.chars().allMatch((c) -> {
            return c == 33 || withinTheRangeOf(c, 35, 91) || withinTheRangeOf(c, 93, 126);
        });
    }

    private static boolean isScopeValid(String scope) {
        return scope == null || scope.chars().allMatch((c) -> {
            return withinTheRangeOf(c, 32, 33) || withinTheRangeOf(c, 35, 91) || withinTheRangeOf(c, 93, 126);
        });
    }

    private static boolean withinTheRangeOf(int c, int min, int max) {
        return c >= min && c <= max;
    }
}
