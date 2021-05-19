package org.xyyh.oidc.provider;

import org.apache.commons.lang3.StringUtils;
import org.xyyh.oidc.core.ApprovalResult;
import org.xyyh.oidc.core.UserApprovalHandler;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;
import org.xyyh.oidc.userdetails.OidcUserDetails;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 默认的授权处理器
 *
 * @author LiDong
 */
public class DefaultUserApprovalHandler implements UserApprovalHandler {


    @Override
    public ApprovalResult preCheck(OidcAuthorizationRequest request, OidcUserDetails user) {
        // 返回一个默认结果，默认结果为未授权
        return ApprovalResult.empty();
    }

    @Override
    public ApprovalResult approval(OidcAuthorizationRequest request, OidcUserDetails user, Map<String, String> approvalParameters) {
        Set<String> requestScopes = request.getScopes();
        Set<String> approvedScopes = new HashSet<>(); // 授权允许的scope
        for (String requestScope : requestScopes) {
            String scopePrefix = "scope.";
            String approvalValue = approvalParameters.get(scopePrefix + requestScope);
            if (StringUtils.equalsIgnoreCase("true", approvalValue)) {
                approvedScopes.add(requestScope);
            }
        }
        return ApprovalResult.of(approvedScopes, request.getRedirectUri());
    }

    @Override
    public void updateAfterApproval(OidcAuthorizationRequest request, OidcUserDetails user, ApprovalResult result) {

    }
}
