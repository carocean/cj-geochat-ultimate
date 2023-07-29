package cj.geochat.ability.oauth.app;

import cj.geochat.ability.api.ResultCode;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;

public class ResultCodeTranslator {
    public static ResultCode translateException(AuthenticationException e){
        ResultCode rc = null;
        if (e instanceof BadCredentialsException) {
            rc = ResultCode.BAD_CREDENTIALS;
        } else if (e instanceof InsufficientAuthenticationException) {
            rc = ResultCode.INSUFFICIENT_AUTHENTICATION;
        } else if (e instanceof SessionAuthenticationException) {
            rc = ResultCode.SESSION_AUTHENTICATION;
        } else if (e instanceof UsernameNotFoundException) {
            rc = ResultCode.USERNAME_NOT_FOUND;
        } else if (e instanceof PreAuthenticatedCredentialsNotFoundException) {
            rc = ResultCode.PRE_AUTHENTICATED_CREDENTIALS;
        } else if (e instanceof AuthenticationServiceException) {
            rc = ResultCode.AUTHENTICATION_SERVICE;
        } else if (e instanceof ProviderNotFoundException) {
            rc = ResultCode.PROVIDER_NOTFOUND;
        } else if (e instanceof AuthenticationCredentialsNotFoundException) {
            rc = ResultCode.AUTHENTICATION_CREDENTIALS;
        } else if (e instanceof RememberMeAuthenticationException) {
            rc = ResultCode.REMEMBER_ME_AUTHENTICATION;
        } else if (e instanceof NonceExpiredException) {
            rc = ResultCode.NONCE_EXPIRED;
        } else if (e instanceof AccountStatusException) {
            rc = ResultCode.ACCOUNT_STATUS;
        } else {
            rc = ResultCode.ERROR_UNKNOWN;
        }
        return rc;
    }
    public static ResultCode translateResultCode(String errorCode){
        ResultCode rc = null;
        if ("invalid_client".equals(errorCode)) {
            rc = ResultCode.INVALID_CLIENT;
        } else if ("unauthorized_client".equals(errorCode)) {
            rc = ResultCode.UNAUTHORIZED_CLIENT;
        } else if ("invalid_grant".equals(errorCode)) {
            rc = ResultCode.INVALID_GRANT;
        } else if ("invalid_scope".equals(errorCode)) {
            rc = ResultCode.INVALID_SCOPE;
        } else if ("invalid_token".equals(errorCode)) {
            rc = ResultCode.INVALID_TOKEN;
        } else if ("invalid_request".equals(errorCode)) {
            rc = ResultCode.INVALID_REQUEST;
        } else if ("redirect_uri_mismatch".equals(errorCode)) {
            rc = ResultCode.REDIRECT_URI_MISMATCH;
        } else if ("unsupported_grant_type".equals(errorCode)) {
            rc = ResultCode.UNSUPPORTED_GRANT_TYPE;
        } else if ("unsupported_response_type".equals(errorCode)) {
            rc = ResultCode.UNSUPPORTED_RESPONSE_TYPE;
        } else {
            rc = ("access_denied".equals(errorCode) ? ResultCode.ACCESS_DENIED : ResultCode.OAUTH2_ERROR);
        }
        return rc;
    }
}