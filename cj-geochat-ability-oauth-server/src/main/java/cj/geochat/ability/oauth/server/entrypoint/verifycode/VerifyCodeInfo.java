package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import lombok.Data;

import java.io.Serializable;

@Data
public class VerifyCodeInfo extends VerifyCodeRequest implements Serializable {
    String code;

    public VerifyCodeInfo() {
    }

    public VerifyCodeInfo(VerifyCodeRequest verifyCodeRequest, String verifyCode) {
        verifyType = verifyCodeRequest.verifyType;
        principal = verifyCodeRequest.principal;
        code = verifyCode;
    }
}
