package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import lombok.Data;

@Data
public class VerifyCodeRequest {
    String verifyType;
    String principal;
}
