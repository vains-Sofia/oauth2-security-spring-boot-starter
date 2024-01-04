package com.vains.authorization.validator;

import com.vains.authorization.basic.captcha.CaptchaValidator;
import com.vains.authorization.basic.captcha.CaptchaValidatorManager;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.List;

/**
 * 验证码校验委托类
 * 根据给定校验器列表验证当前请求，直至某个校验器抛出异常，若无异常则校验通过
 *
 * @author vains 2023/12/13
 */
@Data
@AllArgsConstructor
public class DefaultCaptchaValidatorManager implements CaptchaValidatorManager {

    private List<CaptchaValidator> validators;

    @Override
    public void validate(ServletWebRequest request) {
        for (CaptchaValidator validator : validators) {
            if (validator.supports(request)) {
                validator.validate(request);
            }
        }
    }

}