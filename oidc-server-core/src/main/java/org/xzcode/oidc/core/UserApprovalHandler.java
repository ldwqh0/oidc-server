package org.xzcode.oidc.core;

import org.springframework.security.core.userdetails.UserDetails;
import org.xzcode.oidc.endpoint.request.OidcAuthorizationRequest;

import java.util.Map;

/**
 * 用户授权处理器，用户处理用户的手动授权信息
 */
public interface UserApprovalHandler {

    /**
     * 对请求进行预检
     *
     * @param request 授权请求
     * @param user    授权用户
     * @return 预检结果
     */
    ApprovalResult preCheck(OidcAuthorizationRequest request, UserDetails user);

    /**
     * 根据请求参数对请求进行验证
     *
     * @param request            授权请求
     * @param approvalParameters 用户提交的授权参数
     * @return 授权验证结果
     */
    ApprovalResult approval(OidcAuthorizationRequest request, UserDetails user, Map<String, String> approvalParameters);

    /**
     * 更新某个用户的授权结果
     *
     * @param result 授权请求
     * @param user   授权用户
     */
    void updateAfterApproval(OidcAuthorizationRequest request, UserDetails user, ApprovalResult result);
}
