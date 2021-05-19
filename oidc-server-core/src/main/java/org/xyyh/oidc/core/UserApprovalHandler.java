package org.xyyh.oidc.core;

import org.springframework.security.core.Authentication;
import org.xyyh.oidc.endpoint.request.OpenidAuthorizationRequest;
import org.xyyh.oidc.userdetails.OidcUserDetails;

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
    ApprovalResult preCheck(OpenidAuthorizationRequest request, OidcUserDetails user);

    /**
     * 根据请求参数对请求进行验证
     *
     * @param request            授权请求
     * @param approvalParameters 用户提交的授权参数
     * @return 授权验证结果
     */
    ApprovalResult approval(OpenidAuthorizationRequest request, OidcUserDetails user, Map<String, String> approvalParameters);

    /**
     * 更新某个用户的授权结果
     *
     * @param result 授权请求
     * @param user   授权用户
     */
    void updateAfterApproval(OpenidAuthorizationRequest request, OidcUserDetails user, ApprovalResult result);
}
