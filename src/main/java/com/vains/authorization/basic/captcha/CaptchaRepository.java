package com.vains.authorization.basic.captcha;

import com.vains.authorization.captcha.CaptchaType;
import com.vains.authorization.captcha.BasicCaptcha;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * 验证码repository存储接口
 *
 * @author vains 2023/12/20
 */
public interface CaptchaRepository {

    /**
     * 根据当前请求保存验证码
     *
     * @param captcha 验证码
     * @param request 当前请求
     */
    void save(ServletWebRequest request, BasicCaptcha captcha);

    /**
     * 移除当前请求对应的验证码
     *
     * @param request 当前请求
     * @param type    验证码类型
     */
    void remove(ServletWebRequest request, CaptchaType type);

    /**
     * 根据当前请求获取验证码
     *
     * @param request 当前请求
     * @param type    验证码类型
     * @return 当前请求存储的验证码
     */
    BasicCaptcha get(ServletWebRequest request, CaptchaType type);

}