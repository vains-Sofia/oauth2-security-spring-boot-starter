package com.vains.authorization.constant;

/**
 * 默认常量
 *
 * @author vains 2023/12/18
 */
public final class DefaultConstants {

    public static final String SMS_CAPTCHA_VALIDATE = "sms";

    public static final String EMAIL_CAPTCHA_VALIDATE = "email";

    public static final String IMAGE_CAPTCHA_VALIDATE = "image";

    /**
     * 保存验证码key的前缀
     */
    public static final String CAPTCHA_KEY_PREV = "CAPTCHA_KEY";

    /**
     * 验证码id在请求头中的key
     */
    public static final String CAPTCHA_HEADER_KEY = "deviceId";

    /**
     * 自定义 grant type —— 短信验证码
     */
    public static final String GRANT_TYPE_PASSWORD = "password";

    /**
     * 自定义 grant type —— 密码模式 —— 账号
     */
    public static final String OAUTH_PARAMETER_NAME_USERNAME = "username";

    /**
     * 自定义 grant type —— 短信验证码 —— 密码
     */
    public static final String OAUTH_PARAMETER_NAME_PASSWORD = "password";

    /**
     * 微信登录相关参数——openid：用户唯一id
     */
    public static final String WECHAT_PARAMETER_OPENID = "openid";

    /**
     * 微信登录相关参数——forcePopup：强制此次授权需要用户弹窗确认
     */
    public static final String WECHAT_PARAMETER_FORCE_POPUP = "forcePopup";

    /**
     * 微信登录相关参数——secret：微信的应用秘钥
     */
    public static final String WECHAT_PARAMETER_SECRET = "secret";

    /**
     * 微信登录相关参数——appid：微信的应用id
     */
    public static final String WECHAT_PARAMETER_APPID = "appid";

    /**
     * 三方登录类型——微信
     */
    public static final String THIRD_LOGIN_WECHAT = "wechat";

}