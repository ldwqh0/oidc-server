package org.xyyh.oidc.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.xyyh.oidc.collect.Sets;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 服务发现端点，可以自动发现服务
 */
@RequestMapping("/oauth2/.well-known")
public class ServerDiscoveryEndpoint {

    private final ObjectMapper objectMapper;


    public ServerDiscoveryEndpoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">openid-connect-discovery</a>
     * @see <a href="http://tools.ietf.org/html/rfc5785">rfc5785</a>
     */

    @ResponseBody
    @GetMapping(value = {"openid-configuration"})
    public Map<String, Object> getOpenidConfigurationMap(
        @RequestHeader("host") String host,
        HttpServletRequest request
    ) {
        String scheme = request.getScheme();
        String baseUrl = StringUtils.join(scheme, "://", host, "/oauth2");
        Map<String, Object> result = new HashMap<>();
        // 以下参考google的实现
        result.put("issuer", baseUrl);
        result.put("authorization_endpoint", baseUrl + "/authorize");
//        result.put("device_authorization_endpoint", "");
        result.put("token_endpoint", baseUrl + "/token");
        result.put("userinfo_endpoint", baseUrl + "/userinfo");
        result.put("revocation_endpoint", baseUrl + "/revoke");
        result.put("jwks_uri", baseUrl + "/certs");
        result.put("response_types_supported", Sets.hashSet("code", "code id_token", "id_token"));
        result.put("subject_types_supported", Collections.singleton("public"));
        result.put("id_token_signing_alg_values_supported", Collections.singleton("RS256"));
        result.put("scopes_supported", Sets.hashSet("openid", "profile", "email", "address", "phone"));
        result.put("token_endpoint_auth_methods_supported", Collections.singleton("client_secret_basic"));
        result.put("claims_supported", Sets.hashSet(
            "aud",
            StandardClaimNames.EMAIL,
            StandardClaimNames.EMAIL_VERIFIED,
            "exp",
            StandardClaimNames.FAMILY_NAME,
            StandardClaimNames.GIVEN_NAME,
            "iat",
            "iss",
            StandardClaimNames.LOCALE,
            StandardClaimNames.NAME,
            StandardClaimNames.PICTURE,
            StandardClaimNames.SUB
        ));
        result.put("code_challenge_methods_supported", Sets.hashSet("plain", "S256"));
        result.put("grant_types_supported", Sets.hashSet(
            AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
            AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
            AuthorizationGrantType.REFRESH_TOKEN.getValue()
        ));
        return result;
    }

    /**
     * @see <a href="https://tools.ietf.org/html/draft-ietf-oauth-discovery-10“>https://tools.ietf.org/html/draft-ietf-oauth-discovery-10</a>
     */
    @GetMapping("oauth-authorization-server")
    public String getOs() {
        //TODO 待实现
        return "";
    }
}
