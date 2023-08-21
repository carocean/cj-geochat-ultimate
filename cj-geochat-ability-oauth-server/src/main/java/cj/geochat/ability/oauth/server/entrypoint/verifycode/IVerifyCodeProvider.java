package cj.geochat.ability.oauth.server.entrypoint.verifycode;

public interface IVerifyCodeProvider {
    String generate(VerifyCodeRequest verifyCodeRequest);

}
