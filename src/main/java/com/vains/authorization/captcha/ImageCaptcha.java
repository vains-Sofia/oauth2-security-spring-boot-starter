package com.vains.authorization.captcha;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * 图片验证码
 *
 * @author vains
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class ImageCaptcha extends BasicCaptcha {

    /**
     * 图片base64数据/图片地址
     */
    private String imageData;

}
