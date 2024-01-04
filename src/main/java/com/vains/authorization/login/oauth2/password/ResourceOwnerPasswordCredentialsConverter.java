package com.vains.authorization.login.oauth2.password;

import com.vains.authorization.constant.DefaultConstants;
import com.vains.authorization.util.OAuth2SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Resource Owner passwordParameter Credentials Grant 密码模式参数转换器
 *
 * @author vains 2023/12/27
 */
public class ResourceOwnerPasswordCredentialsConverter implements AuthenticationConverter {

    /**
     * 密码模式的grant type参数名
     */
    @Setter
    private String passwordGrantType = DefaultConstants.GRANT_TYPE_PASSWORD;

    /**
     * 账号参数名
     */
    @Setter
    private String usernameParameter = DefaultConstants.OAUTH_PARAMETER_NAME_USERNAME;

    /**
     * 密码参数名
     */
    @Setter
    private String passwordParameter = DefaultConstants.OAUTH_PARAMETER_NAME_PASSWORD;

    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!this.passwordGrantType.equals(grantType)) {
            return null;
        }

        // 这里目前是客户端认证信息
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // 获取请求中的参数
        MultiValueMap<String, String> parameters = OAuth2SecurityUtils.getParameters(request);

        // scope (OPTIONAL)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
            parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            OAuth2SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE,
                    ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(
                    Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // Mobile phone number / 账号 / 邮箱 (REQUIRED)
        String usernameParameter = parameters.getFirst(this.usernameParameter);
        if (!StringUtils.hasText(usernameParameter) || parameters.get(this.usernameParameter).size() != 1) {
            OAuth2SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "OAuth 2.0 Parameter: " + this.usernameParameter,
                    ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // 密码 (REQUIRED)
        String passwordParameter = parameters.getFirst(this.passwordParameter);
        if (!StringUtils.hasText(passwordParameter) || parameters.get(this.passwordParameter).size() != 1) {
            OAuth2SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "OAuth 2.0 Parameter: " + this.passwordParameter,
                    ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // 提取附加参数
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                !key.equals(OAuth2ParameterNames.CLIENT_ID)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        // 构建AbstractAuthenticationToken子类实例并返回
        return new ResourceOwnerPasswordCredentialsToken(new AuthorizationGrantType(
                this.passwordGrantType), clientPrincipal, requestedScopes, additionalParameters);
    }

}
