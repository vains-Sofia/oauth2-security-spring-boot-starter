package com.vains.authorization.basic.captcha;

import org.springframework.web.context.request.ServletWebRequest;

/**
 * 验证码校验器
 *
 * @author vains 2023/12/20
 */
public interface CaptchaValidator {

    /**
     * 根据当前请求校验验证码
     *
     * @param request 当前请求
     */
    void validate(ServletWebRequest request);

    /**
     * 当前请求是否需要验证码校验
     *
     * @param request 当前请求
     * @return 是否需要建议
     */
    boolean supports(ServletWebRequest request);

}