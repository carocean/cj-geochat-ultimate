package cj.geochat.ability.oauth.server.entrypoint.verifycode.service;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeService;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeInfo;

import java.util.HashMap;
import java.util.Map;

public class DefaultVerifyCodeService implements IVerifyCodeService {
    Map<String, VerifyCodeInfo> verifyCodeInfoMap;

    public DefaultVerifyCodeService() {
        verifyCodeInfoMap = new HashMap<>();
    }

    @Override
    public void save(VerifyCodeInfo verifyCodeInfo) {
        verifyCodeInfoMap.put(verifyCodeInfo.getPrincipal(), verifyCodeInfo);
    }

    @Override
    public VerifyCodeInfo read(String principal) {
        return verifyCodeInfoMap.get(principal);
    }
}
