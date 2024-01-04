package com.vains.authorization.captcha;

import com.vains.authorization.constant.DefaultConstants;

import java.io.Serializable;

/**
 * 验证码类型
 *
 * @author vains 2023/12/21
 */
public record CaptchaType(String value) implements Serializable {

    /**
     * 短信验证码
     */
    public static final CaptchaType SMS_CAPTCHA = new CaptchaType(DefaultConstants.SMS_CAPTCHA_VALIDATE);

    /**
     * 邮箱验证码
     */
    public static final CaptchaType EMAIL_CAPTCHA = new CaptchaType(DefaultConstants.EMAIL_CAPTCHA_VALIDATE);

    /**
     * 图片验证码
     */
    public static final CaptchaType IMAGE_CAPTCHA = new CaptchaType(DefaultConstants.IMAGE_CAPTCHA_VALIDATE);

}