package com.vains.authorization.login.sms;

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
 * 验证码过滤器DSL配置类
 *
 * @author vains 2023/12/14
 */
@Slf4j
@Getter
@Setter
public class SmsCaptchaLoginConfigurer<B extends HttpSecurityBuilder<B>> extends
        AbstractLoginFilterConfigurer<B, SmsCaptchaLoginConfigurer<B>, SmsCaptchaAuthenticationFilter> {

    /**
     * 短信验证码认证登录时手机号的参数名
     */
    private String phoneParameter;

    /**
     * 默认情况下短信认证登录的请求地址
     */
    private static final String DEFAULT_SMS_LOGIN_URL = "/login/sms";

    public SmsCaptchaLoginConfigurer<B> phoneParameter(String phoneParameter) {
        this.phoneParameter = phoneParameter;
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
        SmsLoginAuthenticationProvider authenticationProvider =
                this.getBeanOrNull(SmsLoginAuthenticationProvider.class);
        // 获取到直接返回，获取不到初始化一个默认的
        return authenticationProvider == null
                ? new SmsLoginAuthenticationProvider(this.userDetailsService)
                : authenticationProvider;
    }

    @Override
    public void configure(B http) throws Exception {
        super.configure(http);
        String defaultPhoneParameter = "phone";
        if (ObjectUtils.isEmpty(this.phoneParameter)) {
            this.phoneParameter = defaultPhoneParameter;
        }
        // 配置过滤器参数
        SmsCaptchaAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
        authenticationFilter.setPhoneParameter(this.phoneParameter);
        log.info("Initialization sms captcha login configurer success.");
    }

    public SmsCaptchaLoginConfigurer() {
        super(new SmsCaptchaAuthenticationFilter(), DEFAULT_SMS_LOGIN_URL);
    }

}