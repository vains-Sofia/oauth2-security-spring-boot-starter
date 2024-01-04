package com.vains.authorization.login.email;

import com.vains.authorization.basic.login.AbstractLoginFilterConfigurer;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ObjectUtils;

/**
 * 邮箱验证码登录过滤器DSL配置类
 *
 * @author vains 2023/12/14
 */
@Slf4j
@Getter
@Setter
public class EmailCaptchaLoginConfigurer<B extends HttpSecurityBuilder<B>> extends
        AbstractLoginFilterConfigurer<B, EmailCaptchaLoginConfigurer<B>, EmailCaptchaAuthenticationFilter> {

    /**
     * 邮件验证码认证登录时邮箱的参数名
     */
    private String emailParameter;

    /**
     * 默认情况下邮件认证登录的请求地址
     */
    private static final String DEFAULT_EMAIL_LOGIN_URL = "/login/email";

    public EmailCaptchaLoginConfigurer<B> emailParameter(String emailParameter) {
        this.emailParameter = emailParameter;
        return this;
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    @Override
    protected AuthenticationProvider authenticationProvider(B http) {
        if (this.userDetailsService == null) {
            this.userDetailsService = this.getBeanOrNull(UserDetailsService.class);
        }
        // 先尝试从ioc中获取实例
        EmailLoginAuthenticationProvider authenticationProvider =
                this.getBeanOrNull(EmailLoginAuthenticationProvider.class);
        // 获取到直接返回，获取不到初始化一个默认的
        return authenticationProvider == null
                ? new EmailLoginAuthenticationProvider(this.userDetailsService)
                : authenticationProvider;
    }

    @Override
    public void configure(B http) throws Exception {
        super.configure(http);
        String defaultPhoneParameter = "email";
        if (ObjectUtils.isEmpty(this.emailParameter)) {
            this.emailParameter = defaultPhoneParameter;
        }
        // 配置过滤器参数
        EmailCaptchaAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
        authenticationFilter.setEmailParameter(this.emailParameter);
        log.info("Initialization email captcha login configurer success.");
    }

    public EmailCaptchaLoginConfigurer() {
        super(new EmailCaptchaAuthenticationFilter(), DEFAULT_EMAIL_LOGIN_URL);
    }

}