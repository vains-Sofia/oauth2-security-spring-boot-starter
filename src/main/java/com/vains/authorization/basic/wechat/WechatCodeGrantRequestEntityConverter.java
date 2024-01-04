package com.vains.authorization.basic.wechat;

import com.vains.authorization.constant.DefaultConstants;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.util.MultiValueMap;

/**
 * 微信登录请求token入参处理类
 *
 * @author vains
 */
public class WechatCodeGrantRequestEntityConverter extends OAuth2AuthorizationCodeGrantRequestEntityConverter {

    @Override
    protected MultiValueMap<String, String> createParameters(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        // 如果是微信登录，获取token时携带appid参数与secret参数
        MultiValueMap<String, String> parameters = super.createParameters(authorizationCodeGrantRequest);
        String registrationId = authorizationCodeGrantRequest.getClientRegistration().getRegistrationId();
        if (DefaultConstants.THIRD_LOGIN_WECHAT.equals(registrationId)) {
            // 如果当前是微信登录，携带appid和secret
            parameters.add(DefaultConstants.WECHAT_PARAMETER_APPID, authorizationCodeGrantRequest.getClientRegistration().getClientId());
            parameters.add(DefaultConstants.WECHAT_PARAMETER_SECRET, authorizationCodeGrantRequest.getClientRegistration().getClientSecret());
        }
        return parameters;
    }

}
