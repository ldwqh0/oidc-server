package org.xzcode.oidc.endpoint.request;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-02#section-3.1.1">Response ClientType</a>
 */
public enum OidcAuthorizationResponseType {

    /**
     * oauth2使用的默认的response type
     */
    CODE("code"),
    /**
     * OpenID 使用的 response type
     */
    ID_TOKEN("id_token");

    private final String value;

    public static OidcAuthorizationResponseType from(String value) {
        if ("code".equals(value)) {
            return CODE;
        } else if ("id_token".equals(value)) {
            return ID_TOKEN;
        } else {
            return null;
        }
    }

    OidcAuthorizationResponseType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
