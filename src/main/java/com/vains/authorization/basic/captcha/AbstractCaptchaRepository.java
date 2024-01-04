package com.vains.authorization.basic.captcha;

import com.vains.authorization.captcha.CaptchaType;
import com.vains.authorization.constant.DefaultConstants;
import com.vains.authorization.exception.InvalidCaptchaException;
import com.vains.authorization.property.CaptchaValidateProperties;
import com.vains.authorization.property.ValidateInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.util.ObjectUtils;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * 验证码存储抽象类
 *
 * @author vains 2023/12/26
 */
@RequiredArgsConstructor
public abstract class AbstractCaptchaRepository implements CaptchaRepository {

    private final CaptchaValidateProperties captchaValidateProperties;

    /**
     * 获取缓存的key
     *
     * @param request 当前请求
     * @param type    验证码类型
     * @return 缓存key值
     */
    public String getCaptchaCacheKey(ServletWebRequest request, CaptchaType type) {
        ValidateInfo validateInfo = captchaValidateProperties.getValidate().get(type.value());
        if (validateInfo == null) {
            throw new InvalidCaptchaException("配置中不存在[" + type.value() + "]类型的验证码配置，无法校验.");
        }
        // 获取缓存key
        String cacheKey = validateInfo.getCacheKey();
        // 从请求头获取
        String header = request.getHeader(cacheKey);
        if (ObjectUtils.isEmpty(header)) {
            // 从入参获取
            header = request.getParameter(cacheKey);
            if (ObjectUtils.isEmpty(header)) {
                throw new InvalidCaptchaException("请在请求头中携带[" + cacheKey + "]参数");
            }
        }
        return String.format("%s:%s:%s", DefaultConstants.CAPTCHA_KEY_PREV, type.value(), header);
    }

}