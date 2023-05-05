package cj.geochat.ability.api.exception;

import cj.geochat.ability.api.ResultCode;

public class ApiException extends RuntimeException {

  /**
     * 错误码
     */
  private String code;

  /**
     * 错误信息
     */
  private String message;

  public ApiException() {
    super();
  }

  public ApiException(ResultCode resultCode) {
    super(resultCode.message());
    this.code = resultCode.code();
    this.message = resultCode.message();
  }

  public ApiException(ResultCode resultCode, Throwable cause) {
    super(resultCode.message(), cause);
    this.code = resultCode.code();
    this.message = resultCode.message();
  }

  public ApiException(String message) {
    super(message);
    this.code = "-1";
    this.message = message;
  }

  public ApiException(String code, String message) {
    super(message);
    this.code = code;
    this.message = message;
  }

  public ApiException(String code, String message, Throwable cause) {
    super(message, cause);
    this.code = code;
    this.message = message;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  @Override
  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  @Override
  public synchronized Throwable fillInStackTrace() {
    return this;
  }
}
