package cj.geochat.ability.feign;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.api.exception.ApiException;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import feign.FeignException;
import feign.Response;
import feign.codec.Decoder;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

/**
 * @author andrew jofers
 * @since 2022/4/8
 */
public class ResultDecoder implements Decoder {
    private Decoder decoder;

    public ResultDecoder(Decoder decoder) {
        this.decoder = decoder;
    }

    @Override
    public Object decode(Response response, Type type) throws IOException, FeignException {
        Method method = response.request().requestTemplate().methodMetadata().method();
        boolean isResult = method.getReturnType() != R.class && method.isAnnotationPresent(RequestMapping.class);
        if (isResult) {
//            ParameterizedTypeImpl resultType = ParameterizedTypeImpl.make(R.class, new Type[]{type}, null);
            String resultStr = (String) this.decoder.decode(response, String.class);
//            Type resultType = new TypeToken<R<Type>>() {
//            }.getType();
            Gson gson = new Gson();
            JsonObject resultObj = gson.fromJson(resultStr, JsonObject.class);
            String code = resultObj.get("code").getAsString();
            if (!ResultCode.SUCCESS.code().equals(code)) {
                String message = resultObj.get("message").getAsString();
                throw new ApiException(code, message);
            }
            JsonElement data = resultObj.get("data");
            Object result = new Gson().fromJson(data, type);
            return result;
        }
        return this.decoder.decode(response, type);
    }

//    public Object decode(Response response, Type type) throws IOException, FeignException {
//        Method method = response.request().requestTemplate().methodMetadata().method();
//        boolean isResult = method.getReturnType() != R.class && method.isAnnotationPresent(RequestMapping.class);
//        if (isResult) {
//            Type resultType = TypeToken.getParameterized(R.class, new Type[]{type}).getType();
//            R<?> result = (R)this.decoder.decode(response, resultType);
//            if (!ResultCode.SUCCESS.code().equals(result.getCode())) {
//                throw new ApiException(result.getCode(), result.getMessage());
//            } else {
//                return result.getData();
//            }
//        } else {
//            return this.decoder.decode(response, type);
//        }
//    }
}

