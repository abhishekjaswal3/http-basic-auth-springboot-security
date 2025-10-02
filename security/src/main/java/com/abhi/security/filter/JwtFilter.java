package com.abhi.security.filter;


import com.abhi.security.service.CustomUserDetailServiceSecurity;
import com.abhi.security.utility.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * any request which comes will be filtered once as per oncePerFilterRequest,mtlb ek controller se dusre controller pe agr
 * request ja rhi to bar bar validate nhi krega
 */

/**
 * 🔑 1. HMAC (Symmetric key algorithms)
 *
 * Uses a shared secret key (same key for signing and verifying).
 *
 * Fast, but less secure in distributed systems (since all services must share the same secret).
 *
 * Algorithms:
 *
 * HS256 → HMAC with SHA-256
 *
 * HS384 → HMAC with SHA-384
 *
 * HS512 → HMAC with SHA-512
 *
 * 👉 Example:
 * alg: "HS256"
 *
 * 🔑 2. RSA (Asymmetric key algorithms)
 *
 * Uses a key pair:
 *
 * Private key → signs the token
 *
 * Public key → verifies the token
 *
 * Safer in distributed environments because you don’t need to share the private key.
 *
 * Algorithms:
 *
 * RS256 → RSA with SHA-256
 *
 * RS384 → RSA with SHA-384
 *
 * RS512 → RSA with SHA-512
 *
 * 👉 Example:
 * alg: "RS256"
 *
 * 🔑 3. ECDSA (Elliptic Curve Digital Signature Algorithm)
 *
 * More modern asymmetric cryptography, with smaller keys but similar security strength compared to RSA.
 *
 * Algorithms:
 *
 * ES256 → ECDSA with P-256 and SHA-256
 *
 * ES384 → ECDSA with P-384 and SHA-384
 *
 * ES512 → ECDSA with P-521 and SHA-512
 *
 * 👉 Example:
 * alg: "ES256"
 *
 * 🔑 4. EdDSA (Edwards-curve Digital Signature Algorithm)
 *
 * Newer, very efficient and secure.
 *
 * Uses Edwards curves (Ed25519, Ed448).
 *
 * Example:
 *
 * EdDSA → typically Ed25519
 *
 * 👉 Example:
 * alg: "EdDSA"
 *
 * 🔑 5. None (Unsecured JWTs)
 *
 * alg: "none" → means no signature at all (just base64-encoded header & payload).
 *
 * Very insecure, should never be used in production.
 *
 *
 * | Algorithm       | Type               | Key usage                              | Common Use Case              |
 * | --------------- | ------------------ | -------------------------------------- | ---------------------------- |
 * | HS256/384/512   | HMAC (Symmetric)   | Same key for sign & verify             | Simple apps, trusted parties |
 * | RS256/384/512   | RSA (Asymmetric)   | Private key signs, public key verifies | OAuth2, OpenID Connect       |
 * | ES256/384/512   | ECDSA (Asymmetric) | Private/public key pair                | Modern secure systems        |
 * | EdDSA (Ed25519) | Asymmetric         | Private/public key pair                | High-security, efficient     |
 * | none            | None               | No key                                 | ⚠️ Testing only              |
 */



@Component
public class JwtFilter extends OncePerRequestFilter{
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
