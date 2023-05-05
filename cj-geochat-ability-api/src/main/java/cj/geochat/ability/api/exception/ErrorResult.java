package cj.geochat.ability.api.exception;

import cj.geochat.ability.api.ResultCode;

/**
 * 异常结果包装类
 * @author sw-code
 *
 */
public class ErrorResult {

  private String code;

  private String message;

  private String exception;

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  public String getException() {
    return exception;
  }

  public void setException(String exception) {
    this.exception = exception;
  }

  public static ErrorResult fail(ResultCode resultCode, Throwable e, String message) {
    ErrorResult errorResult = ErrorResult.fail(resultCode, e);
    errorResult.setMessage(message);
    return errorResult;
  }

  public static ErrorResult fail(ResultCode resultCode, Throwable e) {
    ErrorResult errorResult = new ErrorResult();
    errorResult.setCode(resultCode.code());
    errorResult.setMessage(resultCode.message());
    errorResult.setException(e.getClass().getName());
    return errorResult;
  }
  public static ErrorResult fail(String code, String message) {
    ErrorResult errorResult = new ErrorResult();
    errorResult.setCode(code);
    errorResult.setMessage(message);
    return errorResult;
  }
  public static ErrorResult fail(String code, String message,Throwable e) {
    ErrorResult errorResult = new ErrorResult();
    errorResult.setCode(code);
    errorResult.setMessage(message);
    errorResult.setException(e.getClass().getName());
    return errorResult;
  }
}
