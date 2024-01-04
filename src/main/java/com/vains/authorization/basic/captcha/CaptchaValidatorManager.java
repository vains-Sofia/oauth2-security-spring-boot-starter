package com.vains.authorization.basic.captcha;

import org.springframework.web.context.request.ServletWebRequest;

/**
 * 验证码校验管理器
 *
 * @author vains 2023/12/14
 */
public interface CaptchaValidatorManager {

    /**
     * 根据当前请求校验验证码
     *
     * @param request          当前请求
     */
    void validate(ServletWebRequest request);

}