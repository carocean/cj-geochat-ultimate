package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class DelegatingVerifyCodeProvider implements IVerifyCodeProvider {
    List<IVerifyCodeProvider> providers;

    public DelegatingVerifyCodeProvider(List<IVerifyCodeProvider> providers) {
        this.providers = new ArrayList<>();
        this.providers.addAll(providers);
    }

    @Override
    public String generate(VerifyCodeRequest verifyCodeRequest) {
        for (IVerifyCodeProvider provider : providers) {
            String result = provider.generate(verifyCodeRequest);
            if (StringUtils.hasLength(result)) {
                return result;
            }
        }
        return null;
    }

    public void add(IVerifyCodeProvider provider) {
        providers.add(provider);
    }

    public boolean contains(Class<? extends IVerifyCodeProvider> aClass) {
        for (IVerifyCodeProvider provider : providers) {
            if (provider.getClass().equals(aClass)) {
                return true;
            }
        }
        return false;
    }
}
