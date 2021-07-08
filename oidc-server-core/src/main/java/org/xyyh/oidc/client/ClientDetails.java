package org.xyyh.oidc.client;

import org.springframework.lang.Nullable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.io.Serializable;
import java.util.Set;

/**
 * 一个oauth client信息
 */

public interface ClientDetails extends UserDetails, Serializable {

    enum ClientType {
        /**
         * 公共连接，这种连接客户端没有密码
         */
        CLIENT_PUBLIC,
        /**
         * 有密码的连接程序，受保护的连接程序
         */
        CLIENT_CONFIDENTIAL,
        /**
         * 资源服务器
         */
        CLIENT_RESOURCE
    }

    /**
     * 是否自动授权
     */
    boolean isAutoApproval();

    /**
     * 应用access_token过期时间
     *
     * @return 过期时间，单位是秒
     */
    Integer getAccessTokenValiditySeconds();

    /**
     * 应用refresh_token过期时间
     *
     * @return 过期时间，单位是秒
     */
    Integer getRefreshTokenValiditySeconds();

    /**
     * 应用的ID
     */
    String getClientId();

    /**
     * 应用的密钥
     */
    @Nullable
    String getClientSecret();

    /**
     * 应用的scope
     */
    Set<String> getScopes();

    Set<AuthorizationGrantType> getAuthorizedGrantTypes();

    Set<String> getRegisteredRedirectUris();

    ClientType getType();

}
