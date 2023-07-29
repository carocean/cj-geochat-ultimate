package cj.geochat.ability.oauth.gateway.rest;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.io.IOException;
import java.util.Map;

/**
 * spring security 异常处理
 */
@Slf4j
@RestController
public class CustomErrorController implements ErrorController {
    private static final String PATH = "/error";

    @Autowired
    private ErrorAttributes errorAttributes;

    @RequestMapping(value = PATH)
    void error(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.OAUTH2_ERROR;
        // Appropriate HTTP response code (e.g. 404 or 500) is automatically set by Spring.
        // Here we just define response body.
        Map<String, Object> errorMap = getErrorAttributes(request);
        //定义返回格式
        Object obj = R.of(rc, errorMap);
        response.setStatus(HttpServletResponse.SC_OK);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
    }

    public String getErrorPath() {
        return PATH;
    }

    /**
     * 获取请求参数
     * @param request
     * @return
     */
    private Map<String, Object> getErrorAttributes(HttpServletRequest request) {
        WebRequest requestAttributes = new ServletWebRequest(request);
        return errorAttributes.getErrorAttributes(requestAttributes, ErrorAttributeOptions.defaults());
    }

}