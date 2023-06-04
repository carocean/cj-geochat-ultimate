package cj.geochat.ability.util;

public class GeochatRuntimeException extends RuntimeException {
    String code;

    public GeochatRuntimeException(String code, String message) {
        super(message);
        this.code = code;
    }

    public GeochatRuntimeException(String code, Throwable e) {
        super(e.getMessage(), e);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
