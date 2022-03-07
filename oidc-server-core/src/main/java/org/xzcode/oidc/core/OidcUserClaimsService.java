package org.xzcode.oidc.core;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.AddressStandardClaim;
import org.springframework.security.oauth2.core.oidc.DefaultAddressStandardClaim;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.util.*;

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.*;
import static org.xzcode.oidc.core.MapUtils.copyValueByKey;

/**
 * OidcUserClaimsService
 */
public interface OidcUserClaimsService {

    /**
     * 根据用户的授权信息获取{@link OidcUserInfo}
     *
     * @param user {@link UserDetails} ,can not be null.
     * @see UserDetails
     * @see OidcUserInfo
     */
    OidcUserInfo loadOidcUserInfo(UserDetails user);

    /**
     * 根据认证信息{@link OidcAuthentication}获取 user claims
     *
     * @param authentication 用户的认证信息
     * @see OidcAuthentication
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Oidc Claims</a>
     */
    default Map<String, ?> loadClaims(OidcAuthentication authentication) {
        Set<String> scopes = authentication.getScopes();
        UserDetails user = (UserDetails) authentication.getPrincipal();
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> userClaims = this.loadOidcUserInfo(user).getClaims();
        copyValueByKey(userClaims, result, SUB);
        if (scopes.contains(OidcScopes.PROFILE)) {
            copyValueByKey(userClaims, result,
                NAME, GIVEN_NAME, FAMILY_NAME, MIDDLE_NAME, NICKNAME, PREFERRED_USERNAME,
                PROFILE, PICTURE, WEBSITE, GENDER, BIRTHDATE,
                ZONEINFO, LOCALE, UPDATED_AT
            );
            result.put("roles", user.getAuthorities());
        }
        if (scopes.contains(OidcScopes.EMAIL)) {
            copyValueByKey(userClaims, result, EMAIL, EMAIL_VERIFIED);
        }
        if (scopes.contains(OidcScopes.ADDRESS)) {
            Object object = userClaims.get(ADDRESS);
            if (Objects.nonNull(object)) {
                if (object instanceof AddressStandardClaim) {
                    AddressStandardClaim addressClaim = (AddressStandardClaim) object;
                    AddressStandardClaim copied = new DefaultAddressStandardClaim.Builder()
                        .formatted(addressClaim.getFormatted())
                        .streetAddress(addressClaim.getStreetAddress())
                        .locality(addressClaim.getLocality())
                        .region(addressClaim.getRegion())
                        .postalCode(addressClaim.getPostalCode())
                        .country(addressClaim.getCountry())
                        .build();
                    result.put(ADDRESS, copied);
                } else if (object instanceof Map) {
                    result.put(ADDRESS, new DefaultAddressStandardClaim.Builder((Map<String, Object>) object).build());
                } else {
                    copyValueByKey(userClaims, result, ADDRESS);
                }
            }
        }
        if (scopes.contains(OidcScopes.PHONE)) {
            copyValueByKey(userClaims, result, PHONE_NUMBER, PHONE_NUMBER_VERIFIED);
        }
        return Collections.unmodifiableMap(result);
    }
}

final class MapUtils {
    private MapUtils() {

    }

    public static void copyValueByKey(Map<String, Object> source, Map<String, Object> target, String... names) {
        for (String name : names) {
            Object value = source.get(name);
            if (ObjectUtils.isNotEmpty(value)) {
                target.put(name, value);
            }
        }
    }
}

