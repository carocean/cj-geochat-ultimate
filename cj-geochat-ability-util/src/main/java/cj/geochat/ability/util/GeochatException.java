package cj.geochat.ability.util;

public class GeochatException extends Exception {
    String code;

    public GeochatException(String code, String message) {
        super(message);
        this.code = code;
    }

    public GeochatException(String code, Throwable e) {
        super(e.getMessage(), e);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
