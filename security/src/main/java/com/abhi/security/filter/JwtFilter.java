package com.abhi.security.filter;


import com.abhi.security.service.CustomUserDetailServiceSecurity;
import com.abhi.security.utility.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * any request which comes will be filtered once as per oncePerFilterRequest,mtlb ek controller se dusre controller pe agr
 * request ja rhi to bar bar validate nhi krega
 */

/**
 * 🔑 1. HMAC (Symmetric key algorithms)
 * <p>
 * Uses a shared secret key (same key for signing and verifying).
 * <p>
 * Fast, but less secure in distributed systems (since all services must share the same secret).
 * <p>
 * Algorithms:
 * <p>
 * HS256 → HMAC with SHA-256
 * <p>
 * HS384 → HMAC with SHA-384
 * <p>
 * HS512 → HMAC with SHA-512
 * <p>
 * 👉 Example:
 * alg: "HS256"
 * <p>
 * 🔑 2. RSA (Asymmetric key algorithms)
 * <p>
 * Uses a key pair:
 * <p>
 * Private key → signs the token
 * <p>
 * Public key → verifies the token
 * <p>
 * Safer in distributed environments because you don’t need to share the private key.
 * <p>
 * Algorithms:
 * <p>
 * RS256 → RSA with SHA-256
 * <p>
 * RS384 → RSA with SHA-384
 * <p>
 * RS512 → RSA with SHA-512
 * <p>
 * 👉 Example:
 * alg: "RS256"
 * <p>
 * 🔑 3. ECDSA (Elliptic Curve Digital Signature Algorithm)
 * <p>
 * More modern asymmetric cryptography, with smaller keys but similar security strength compared to RSA.
 * <p>
 * Algorithms:
 * <p>
 * ES256 → ECDSA with P-256 and SHA-256
 * <p>
 * ES384 → ECDSA with P-384 and SHA-384
 * <p>
 * ES512 → ECDSA with P-521 and SHA-512
 * <p>
 * 👉 Example:
 * alg: "ES256"
 * <p>
 * 🔑 4. EdDSA (Edwards-curve Digital Signature Algorithm)
 * <p>
 * Newer, very efficient and secure.
 * <p>
 * Uses Edwards curves (Ed25519, Ed448).
 * <p>
 * Example:
 * <p>
 * EdDSA → typically Ed25519
 * <p>
 * 👉 Example:
 * alg: "EdDSA"
 * <p>
 * 🔑 5. None (Unsecured JWTs)
 * <p>
 * alg: "none" → means no signature at all (just base64-encoded header & payload).
 * <p>
 * Very insecure, should never be used in production.
 * <p>
 * <p>
 * | Algorithm       | Type               | Key usage                              | Common Use Case              |
 * | --------------- | ------------------ | -------------------------------------- | ---------------------------- |
 * | HS256/384/512   | HMAC (Symmetric)   | Same key for sign & verify             | Simple apps, trusted parties |
 * | RS256/384/512   | RSA (Asymmetric)   | Private key signs, public key verifies | OAuth2, OpenID Connect       |
 * | ES256/384/512   | ECDSA (Asymmetric) | Private/public key pair                | Modern secure systems        |
 * | EdDSA (Ed25519) | Asymmetric         | Private/public key pair                | High-security, efficient     |
 * | none            | None               | No key                                 | ⚠️ Testing only              |
 */


@Component
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private CustomUserDetailServiceSecurity userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }
        if (username != null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(jwt)) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        // response.addHeader("admin","abhi"); //if u want to set header in response this value will also be there
        //we sent in chain of filter for further processing if any filter present
        chain.doFilter(request, response);
    }
}
