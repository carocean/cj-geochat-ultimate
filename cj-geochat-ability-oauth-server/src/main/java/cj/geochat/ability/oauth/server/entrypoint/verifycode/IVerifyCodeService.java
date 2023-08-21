package cj.geochat.ability.oauth.server.entrypoint.verifycode;

public interface IVerifyCodeService {
    void save(VerifyCodeInfo verifyCodeInfo);

    VerifyCodeInfo read(String principal);
}
