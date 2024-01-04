package com.vains.authorization.configurer;

import com.vains.authorization.captcha.CaptchaAuthorizationConfigurer;
import com.vains.authorization.login.email.EmailCaptchaLoginConfigurer;
import com.vains.authorization.login.sms.SmsCaptchaLoginConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * 暴露出去的验证码认证登录过滤器配置类
 *
 * @author vains 2023/12/15
 */
public class BasicLoginConfigurer extends AbstractHttpConfigurer<BasicLoginConfigurer, HttpSecurity> {

    private SmsCaptchaLoginConfigurer<HttpSecurity> smsCaptchaLoginConfigurer;

    private EmailCaptchaLoginConfigurer<HttpSecurity> emailCaptchaLoginConfigurer;

    private CaptchaAuthorizationConfigurer<HttpSecurity> captchaAuthorizationConfigurer;

    public BasicLoginConfigurer smsCaptchaLogin(
            Customizer<SmsCaptchaLoginConfigurer<HttpSecurity>> smsCaptchaLoginCustomizer) {
        smsCaptchaLoginConfigurer = new SmsCaptchaLoginConfigurer<>();
        smsCaptchaLoginCustomizer.customize(smsCaptchaLoginConfigurer);
        return this;
    }

    public BasicLoginConfigurer emailCaptchaLogin(
            Customizer<EmailCaptchaLoginConfigurer<HttpSecurity>> emailCaptchaLoginCustomizer) {
        emailCaptchaLoginConfigurer = new EmailCaptchaLoginConfigurer<>();
        emailCaptchaLoginCustomizer.customize(emailCaptchaLoginConfigurer);
        return this;
    }

    public BasicLoginConfigurer captchaAuthorization(
            Customizer<CaptchaAuthorizationConfigurer<HttpSecurity>> captchaAuthorizationCustomizer) {
        captchaAuthorizationConfigurer = new CaptchaAuthorizationConfigurer<>();
        captchaAuthorizationCustomizer.customize(captchaAuthorizationConfigurer);
        return this;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        if (this.smsCaptchaLoginConfigurer != null) {
            builder.with(this.smsCaptchaLoginConfigurer, Customizer.withDefaults());
        }
        if (this.emailCaptchaLoginConfigurer != null) {
            builder.with(this.emailCaptchaLoginConfigurer, Customizer.withDefaults());
        }
        if (this.captchaAuthorizationConfigurer != null) {
            builder.with(this.captchaAuthorizationConfigurer, Customizer.withDefaults());
        }

        // 如果有验证码登录，但是没有验证码过滤器配置，则默认初始化
        if ((this.smsCaptchaLoginConfigurer != null ||
             this.emailCaptchaLoginConfigurer != null) &&
            this.captchaAuthorizationConfigurer == null) {
            this.captchaAuthorizationConfigurer = new CaptchaAuthorizationConfigurer<>();
            builder.with(this.captchaAuthorizationConfigurer, Customizer.withDefaults());
        }
    }
}