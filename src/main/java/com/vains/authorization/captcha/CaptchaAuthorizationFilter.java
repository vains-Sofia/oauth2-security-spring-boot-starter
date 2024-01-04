package com.vains.authorization.captcha;

import com.vains.authorization.basic.captcha.CaptchaValidatorManager;
import com.vains.authorization.exception.InvalidCaptchaException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

/**
 * 验证码校验过滤器
 *
 * @author vains 2023/12/13
 */
@Slf4j
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
public class CaptchaAuthorizationFilter extends GenericFilterBean {

    private CaptchaValidatorManager captchaValidatorManager;

    /**
     * 需要校验验证码的请求
     */
    private RequestMatcher requiresAuthenticationRequestMatcher;

    private AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!requiresAuthenticationRequestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            // 验证码校验
            captchaValidatorManager.validate(new ServletWebRequest(request, response));
            // 验证成功后执行下一个过滤器
            chain.doFilter(request, response);
        } catch (InvalidCaptchaException e) {
            if (log.isDebugEnabled()) {
                log.debug("接口[{}]验证码校验失败.原因：{}", request.getRequestURI(), e.getMessage());
            }
            authenticationFailureHandler.onAuthenticationFailure(request, response, e);
        }
    }

}