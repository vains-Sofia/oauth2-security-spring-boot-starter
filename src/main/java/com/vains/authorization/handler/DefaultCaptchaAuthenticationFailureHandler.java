package com.vains.authorization.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.io.IOException;
import java.util.Map;

/**
 * 默认验证码校验异常处理
 *
 * @author vains 2023/12/14
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultCaptchaAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ErrorAttributes errorAttributes;

    private final HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter();

    private final AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler("/login");

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        if (request.getHeader(HttpHeaders.ACCEPT).contains(MediaType.TEXT_HTML_VALUE)) {
            // 如果是页面，重定向
            this.failureHandler.onAuthenticationFailure(request, response, exception);
        } else {
            // 获取异常信息
            Map<String, Object> body = getErrorAttributes(request, ErrorAttributeOptions.defaults());
            body.put("status", HttpStatus.UNAUTHORIZED.value());
            body.put("message", exception.getMessage());
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
            this.converter.write(body, MediaType.APPLICATION_JSON, httpResponse);
        }
    }

    protected Map<String, Object> getErrorAttributes(HttpServletRequest request, ErrorAttributeOptions options) {
        WebRequest webRequest = new ServletWebRequest(request);
        return this.errorAttributes.getErrorAttributes(webRequest, options);
    }
}