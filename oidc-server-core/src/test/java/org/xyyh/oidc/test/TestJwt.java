package org.xyyh.oidc.test;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class TestJwt {

    @Test
    public void testGenerateJwt() throws JOSEException, ParseException {
        JWK jwk = keyset().getKeyByKeyId("default-sign");
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS512);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .claim("A", "b")
            .claim("bad", "")
            .build();
        SignedJWT jwt = new SignedJWT(header, claimsSet);
        PrivateKey rsaKey = jwk.toRSAKey().toPrivateKey();
        RSAPublicKey publicKey = jwk.toRSAKey().toRSAPublicKey();
        JWSSigner signer = new RSASSASigner(rsaKey);
        jwt.sign(signer);
        String token = jwt.serialize();

        SignedJWT jwt2 = SignedJWT.parse(token);
        boolean result = jwt2.verify(new RSASSAVerifier(publicKey));
        System.out.println(result);
        System.out.println(jwt2.getJWTClaimsSet());
        System.out.println(jwt.serialize());

    }


    public JWKSet keyset() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("default-sign")
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS512)
            .generate();
        return new JWKSet(rsaKey);
    }

    @Test
    public void testJwe() throws JOSEException, ParseException {
        RSAKey jwk = keyset().getKeyByKeyId("default-sign").toRSAKey();
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        JWEObject object = new JWEObject(header, new Payload("adsf"));
        JWEEncrypter encryptedJWE = new RSAEncrypter(jwk.toRSAPublicKey());
        object.encrypt(encryptedJWE);
        String o = object.serialize();

        JWEObject oin = JWEObject.parse(o);
        oin.decrypt(new RSADecrypter(jwk.toRSAPrivateKey()));

        System.out.println(o);
    }
}
