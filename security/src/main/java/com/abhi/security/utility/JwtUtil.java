package com.abhi.security.utility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    Path privateKeyPath = Paths.get("src/main/resources/keys/private.pem");
    Path publicKeyPath = Paths.get("src/main/resources/keys/public.pem");
    PrivateKey privateKey = PemUtils.readPrivateKey(privateKeyPath); //for RS256
    PublicKey publicKey = PemUtils.readPublicKey(publicKeyPath); //for RS256
    private String SECRET_KEY = "TaK+HaV^uvCHEFsEVfypW#7g9^k*Z8$V"; //this HS256 algo key ;should be not more than 32 bytes

    public JwtUtil() throws Exception {
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getSubject();
    }

    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
               // .verifyWith(getSigningKey()) //this for HS256
                .verifyWith(publicKey) //RS256
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .header().empty().add("typ","JWT")
                .and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 5 minutes expiration time
             //   .signWith(getSigningKey()) // this was forHS256 Algo
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
        //Finally .compact() → creates the JWT string (header.payload.signature).
    }

    public Boolean validateToken(String token) {
        return !isTokenExpired(token);
    }


}
