package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import cj.geochat.ability.oauth.server.annotation.CjVerifyType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class DelegatingVerifyCodeRequestResolver implements IVerifyCodeRequestResolver {
    Map<String, IVerifyCodeRequestResolver> resolverMap;

    public DelegatingVerifyCodeRequestResolver(List<IVerifyCodeRequestResolver> resolvers) {
        resolverMap = new HashMap<>();
        for (IVerifyCodeRequestResolver resolver : resolvers) {
            add(resolver);
        }
    }

    @Override
    public VerifyCodeRequest resolve(HttpServletRequest request) {
       String verify_type= request.getParameter("verify_type");
        if (!StringUtils.hasLength(verify_type)) {
            verify_type = "guest_code";
        }
        IVerifyCodeRequestResolver resolver = resolverMap.get(verify_type);
        if (resolver == null) {
            return null;
        }
        return resolver.resolve(request);
    }

    public void add(IVerifyCodeRequestResolver verifyCodeRequestResolver) {
        CjVerifyType cjVerifyType = verifyCodeRequestResolver.getClass().getAnnotation(CjVerifyType.class);
        if (cjVerifyType == null) {
            log.warn("添加验证码解析器失败。" + verifyCodeRequestResolver.getClass().getName());
            return;
        }
        resolverMap.put(cjVerifyType.value(),verifyCodeRequestResolver);
    }

    public boolean containsValue(Class<? extends IVerifyCodeRequestResolver> clazz) {
        for (IVerifyCodeRequestResolver resolver : resolverMap.values()) {
            if (clazz.equals(resolver.getClass())) {
                return true;
            }
        }
        return false;
    }
}
