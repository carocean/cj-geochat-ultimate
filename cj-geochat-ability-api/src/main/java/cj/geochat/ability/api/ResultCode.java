package cj.geochat.ability.api;

public enum ResultCode {

  /* 成功状态码 */
  SUCCESS("2000", "ok"),
  /* 参数错误 */
  PARAM_IS_INVALID("1001", "invalid_parameter"),
  PARAM_IS_BLANK("1002", "null_parameter"),
  PARAM_TYPE_BIND_ERROR("1003", "error_type_parameter"),
  PARAM_NOT_COMPLETE("1004", "require_parameter"),
  /* 用户错误 2001-2999*/
  INVALID_REQUEST("2001", "invalid_request"),
  INVALID_CLIENT("2002", "invalid_client"),
  INVALID_GRANT("2003", "invalid_grant"),
  UNAUTHORIZED_CLIENT("2004", "unauthorized_client"),
  UNSUPPORTED_GRANT_TYPE("2005", "unsupported_grant_type"),
  INVALID_SCOPE("2006", "invalid_scope"),
  INSUFFICIENT_SCOPE("2007", "insufficient_scope"),
  INVALID_TOKEN("2008", "invalid_token"),
  REDIRECT_URI_MISMATCH("2009", "redirect_uri_mismatch"),
  UNSUPPORTED_RESPONSE_TYPE("2010", "unsupported_response_type"),
  ACCESS_DENIED("2011", "access_denied"),
  OAUTH2_ERROR("2012", "error"),

  BAD_CREDENTIALS("2013", "bad_credentials"),
  INSUFFICIENT_AUTHENTICATION("2014", "insufficient_authentication"),
  SESSION_AUTHENTICATION("2015", "session_authentication"),
  USERNAME_NOT_FOUND("2016", "username_notfound"),
  PRE_AUTHENTICATED_CREDENTIALS("2017", "pre_authenticated_credentials_notfound"),
  AUTHENTICATION_SERVICE("2018", "authentication_service"),
  PROVIDER_NOTFOUND("2019", "provider_notfound"),
  AUTHENTICATION_CREDENTIALS("2020", "authentication_credentials_notfound"),
  REMEMBER_ME_AUTHENTICATION("2021", "remember_me_authentication"),
  NONCE_EXPIRED("2022", "nonce_expired"),
  ACCOUNT_STATUS("2023", "account_status"),

  IS_AUTHORIZED("2030", "is_authorized"),
  IS_LOGOUT("2031", "is_logout"),
  IS_LOGOUT_FAILURE("2032", "is_logout_failure"),
  REQ_TOKEN_FAILURE("2033", "req_token_failure"),
  CONFIRM_ACCESS("2034", "oauth_confirm_access"),
  ERROR_UNKNOWN("2040", "unknown"),
  /* 系统及http协议错误 4001-4999*/
  SYSTEM_ERROR("4005", "system_error"),
  NOTFOUND_ERROR("4004", "not_found");

  private String code;
  private String message;

  private ResultCode(String code, String message) {
    this.code = code;
    this.message = message;
  }

  public String code() {
    return this.code;
  }
  public String message() {
    return this.message;
  }
}
