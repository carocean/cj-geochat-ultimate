package cj.geochat.ability.oauth.gateway.util;

import java.util.Map;

public class QueryStringUtils {
    public static String queryString(Map<String,?> params){
        StringBuffer sb = new StringBuffer();
        for (String key : params.keySet()) {
            String value = params.get(key)+"";
            sb.append(key);
            sb.append("=");
            sb.append(value);
            sb.append("&");
        }
        if (sb.lastIndexOf("&") == sb.length()-1) {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }
}
