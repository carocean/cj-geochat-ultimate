package cj.geochat.ability.oauth.server.entrypoint.verifycode.provider;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeProvider;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeRequest;
import com.github.f4b6a3.ulid.UlidCreator;
import org.apache.commons.codec.binary.Hex;

import java.util.Random;

public class GuestVerifyCodeProvider implements IVerifyCodeProvider {
    @Override
    public String generate(VerifyCodeRequest verifyCodeRequest) {
        if (!"guest_code".equals(verifyCodeRequest.getVerifyType())) {
            return null;
        }
        Hex hex = new Hex();
        byte[] b = hex.encode(UlidCreator.getUlid().toLowerCase().getBytes());
        String account = new String(b);
        verifyCodeRequest.setPrincipal(String.format("0x%s", account));
        Random random = new Random();
        String code = String.format("%s%s%s%s%s%s",
                random.nextInt(10),
                random.nextInt(10),
                random.nextInt(10),
                random.nextInt(10),
                random.nextInt(10),
                random.nextInt(10));
        return code;
    }
}
