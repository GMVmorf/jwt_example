package ru.mgprojects.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.lang.Assert;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class SecretService {

    public static final String STATUS_OK = "OK";
    public static final String STATUS_EXPIRED = "EXPIRED";
    public static final String TOKEN_EXPIRED_MESSAGE = "Token is expired.";

    private Map<String, String> secrets = new HashMap<>();

    private SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
        @Override
        public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
            return TextCodec.BASE64.decode(secrets.get(header.getAlgorithm()));
        }
    };

    @PostConstruct
    public void setup() {
        refreshSecrets();
    }

    public SigningKeyResolver getSigningKeyResolver() {
        return signingKeyResolver;
    }

    public Map<String, String> getSecrets() {
        return secrets;
    }

    public void setSecrets(Map<String, String> secrets) {
        Assert.notNull(secrets);

        this.secrets.putAll(secrets);
    }

    public byte[] getSecretBytesByAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        final String signatureAlgorithmString = signatureAlgorithm.getValue();

        if (secrets.containsKey(signatureAlgorithmString)) {
            return TextCodec.BASE64.decode(secrets.get(signatureAlgorithmString));
        } else {
            throw new RuntimeException("Signature algorithm [ " + signatureAlgorithmString + " ] is not found.");
        }
    }

    public byte[] getHS256SecretBytes() {
        return TextCodec.BASE64.decode(secrets.get(SignatureAlgorithm.HS256.getValue()));
    }

    public byte[] getHS384SecretBytes() {
        return TextCodec.BASE64.decode(secrets.get(SignatureAlgorithm.HS384.getValue()));
    }

    public byte[] getHS512SecretBytes() {
        return TextCodec.BASE64.decode(secrets.get(SignatureAlgorithm.HS512.getValue()));
    }

    public String generateToken(SignatureAlgorithm signatureAlgorithm, Map<String, Object> claims) {
        String jwtId = UUID.randomUUID().toString().replace("-", "");
        Date now = new Date();
        Date expirationDate = new Date(System.currentTimeMillis() + (1000 * 5)); // 30 seconds

        String jws = Jwts.builder()
                .setId(jwtId)
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, getSecretBytesByAlgorithm(signatureAlgorithm))
                .compact();

        return jws;
    }

    public String parseToken(String token) {

        try {
            Jws<Claims> jws = Jwts.parser()
                    .setSigningKeyResolver(getSigningKeyResolver())
                    .parseClaimsJws(token);
        } catch (ExpiredJwtException eje) {
            return STATUS_EXPIRED;
        }

        return STATUS_OK;
    }

    public Map<String, String> refreshSecrets() {
        SecretKey key = MacProvider.generateKey(SignatureAlgorithm.HS256);
        secrets.put(SignatureAlgorithm.HS256.getValue(), TextCodec.BASE64.encode(key.getEncoded()));
        key = MacProvider.generateKey(SignatureAlgorithm.HS384);
        secrets.put(SignatureAlgorithm.HS384.getValue(), TextCodec.BASE64.encode(key.getEncoded()));
        key = MacProvider.generateKey(SignatureAlgorithm.HS512);
        secrets.put(SignatureAlgorithm.HS512.getValue(), TextCodec.BASE64.encode(key.getEncoded()));
        return secrets;
    }
}
