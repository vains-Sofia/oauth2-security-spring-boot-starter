package com.vains.authorization.captcha;

import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * 验证码
 *
 * @author vains 2023/12/20
 */
@Data
public class BasicCaptcha implements Serializable {

    /**
     * 验证码
     */
    private String code;

    /**
     * 验证码类型
     */
    private CaptchaType type;

    /**
     * 过期时间
     */
    private LocalDateTime expireTime;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expireTime);
    }

}