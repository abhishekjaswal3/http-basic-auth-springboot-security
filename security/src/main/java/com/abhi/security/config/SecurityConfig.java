package com.abhi.security.config;

import com.abhi.security.filter.JwtFilter;
import com.abhi.security.service.CustomUserDetailServiceSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

/**
 * NOTES for security flow
 * HTTP Request → Tomcat → FilterChainProxy → BasicAuthenticationFilter
 *     ↓
 * AuthenticationManager → UserDetailsService → validate username/password
 *     ↓
 * SecurityContext updated
 *     ↓
 * DispatcherServlet → @RestController
 *     ↓
 * HTTP Response
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailServiceSecurity userDetailsService;

    @Autowired
    JwtFilter jwtFilter;



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/user/above-all").hasRole("ADMIN")
                .antMatchers("/user/**").authenticated()
                .anyRequest().permitAll();
                //.and().httpBasic();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().csrf().disable();
        //JWT implemented -check for jwt token before it goes to controller,basically jwt filter will work before this
        //UsernamePasswordAuthenticationFilter as we have removed basic authentication
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
 }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }


   /* @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Spring Security recommends using DelegatingPasswordEncoder(for this default encryption is bcrypt only),
     * which lets you support multiple encoders and switch algorithms without breaking existing passwords.
     * This sets bcrypt as the default but also understands other encoders.
     * stored password will look like:
     *
     * {bcrypt}$2a$10$....
     * {argon2}$argon2id$v=19$m=4096,t=3,p=1$....
     * When verifying, Spring checks the prefix and uses the right encoder automatically.
     * we can also add code to turn existing password say bcrypt to argon2 by adding methods.
     *
     *
     * @Bean
     *     public PasswordEncoder passwordEncoder() {
     *         return PasswordEncoderFactories.createDelegatingPasswordEncoder();
     *
     */

    /**
     * Spring Boot 2.6 comes with Spring Security 5.6.x, — the defaultsForSpringSecurity_v5_8() methods are not available in your version.
     *
     * That means you’ll need to manually configure the password encoder with parameters instead of relying on the new defaults.
     *Parameter Meaning
     *
     * saltLength (16–32 bytes) → random sequence of byte thats get added to  password before hashing.
     *
     * hashLength (32 bytes) → length of the hash output(size of the derived key).
     *
     * parallelism (1–4) → CPU threads used. Keep 1 for most apps unless heavy servers
     * (Parallelism defines how many threads (lanes) Argon2 uses while computing the hash).
     * How it works
     *
     * If parallelism = 1: Argon2 uses one thread (serial computation).
     *
     * If parallelism = 2: Argon2 splits the memory into 2 lanes and computes in parallel.
     *
     * Higher values mean faster hashing on multi-core CPUs but also allow attackers to
     * parallelize their cracking attempts on GPUs/ASICs.
     * {1 → safest & most portable (always works, no assumption about CPU cores).
     *
     * 2–4 → reasonable on servers with multiple cores (can improve performance without weakening security much).
     *
     * >4 → usually unnecessary, doesn’t add security, may only speed things up for attackers too.}
     *
     *
     * memory (KB) → how much RAM each hash requires. 1 << 12 = 4096 KB = 4 MB. You can increase for stronger security (e.g., 1 << 15 = 32 MB).
     *{
     * it forces both the defender (your server) and the attacker (e.g., GPU cracker) to
     * allocate significant memory for each hash attempt.
     * Typical Ranges
     *
     * 4 MB – 32 MB → reasonable defaults for web applications.
     *
     * 64 MB – 256 MB → strong security if you can afford it (e.g., admin systems, password managers).
     *
     * >1 GB → overkill for web logins (users will notice slowness, servers will struggle).}
     *
     * iterations (>=3) → number of iterations (time cost). Higher = slower = more secure.
     * {🔑 What iterations (time cost) mean
     *
     * Iterations = how many times the algorithm repeats its internal compression/processing steps.
     *
     * Increasing iterations makes each hash take longer (CPU time) — increasing attacker cost proportionally.
     *
     * Unlike memory, which raises RAM requirements, iterations raise time/CPU cost.
     *
     * ⚖️ Security vs. performance
     *
     * Higher iterations → more secure (slower to brute force).
     *
     * Higher iterations → slower login/registration on your servers.
     *
     * Pick a number that slows attackers but keeps user-facing latency acceptable and avoids DoS risks.
     *
     * ✅ Typical values for Argon2 (practical)
     *
     * 1–2: low (fast). Use for low-security or resource-constrained systems.
     *
     * 3–4: sensible default for most web apps. Good balance of security and performance.
     *
     * 5–10+: higher security (admin portals, vaults) — only if your servers can handle it.
     *
     * In many production setups people choose 3 as a good default }
     */
    @Bean
    public PasswordEncoder passwordEncoder() {

        Map<String, PasswordEncoder> encoders = new HashMap<>();
        // these keys 'argon2', 'bcrypt' are added so that later it can be identified which type of password decryption is needed
        // to match the password.but this works if we have earlier different encoder for which we saved the password and now its different.
        //but we want to allow the old encryption instead of changing password
        // Argon2 (manual config since we're on Spring 2.6 / Security 5.6)
        encoders.put("argon2", new Argon2PasswordEncoder(
                16,     // salt length
                32,     // hash length
                1,      // parallelism
                1 << 13, // memory = 8192 KB (8 MB)
                3       // iterations
        ));

        // Bcrypt (existing users)
        encoders.put("bcrypt", new BCryptPasswordEncoder());

        // Set Argon2 as the default encoder for NEW passwords
        return new DelegatingPasswordEncoder("argon2", encoders);
    }
    }



    /**
     * 1. BCryptPasswordEncoder
     *
     * Algorithm: BCrypt (adaptive hashing with built-in salt).
     *
     * Strengths:
     *
     * Widely used and trusted (default in Spring Security for years).
     *
     * Adjustable work factor (strength), making brute force harder.
     *
     * Resistant to rainbow table attacks.
     *
     * Weaknesses:
     *
     * Only CPU-hard (not memory-hard), so GPUs/ASICs can crack faster.
     *[ When we say an algorithm is memory-hard, we mean:
     *
     * ➡️ It requires a lot of memory (RAM) as part of its computation, not just CPU cycles.
     * Why does this matter?
     *
     * Attackers often use GPUs, ASICs, or FPGAs to crack passwords because those can compute billions of hashes per second.
     *
     * GPUs are excellent at parallel CPU operations, but they don’t have much memory per core.
     *
     * A memory-hard algorithm forces each hashing operation to use a significant amount of RAM.
     *
     * This makes it much harder (and more expensive) to scale attacks on GPUs/ASICs, because memory becomes the bottleneck.]
     *
     * When to use:
     *
     * General-purpose web apps.
     *
     * You need a balance of security and performance.
     *
     * Great default if you don’t have strict compliance requirements.
     *
     *
     * 2. Argon2PasswordEncoder
     *
     * Algorithm: Argon2id (winner of the Password Hashing Competition).
     *
     * Strengths:
     *
     * Memory-hard → resistant to GPU/ASIC cracking.()
     *
     * Tunable parameters: iterations (time), memory cost, parallelism.
     *
     * Future-proof, recommended in modern cryptography.
     *
     * Weaknesses:
     *
     * Slightly heavier on memory/CPU vs. BCrypt.
     *
     * When to use:
     *
     * Security-critical apps (finance, healthcare, government).
     *
     * New applications where you can enforce Argon2 from day one.
     *
     * If you want top-tier password hashing.
     *
     *
     * 3. PBKDF2PasswordEncoder
     *
     * Algorithm: PBKDF2 (Password-Based Key Derivation Function 2).
     *
     * Strengths:
     *
     * Industry standard (NIST, PKCS #5).
     *
     * Configurable iterations and key length.
     *
     * Easy to get FIPS 140-2 compliance (important in enterprise/government).
     *
     * Weaknesses:
     *
     * CPU-bound (weaker against GPU attacks than Argon2/scrypt).
     *
     * When to use:
     *
     * Enterprise/government environments requiring NIST compliance.
     *
     * Interoperability with other systems already using PBKDF2.
     *
     * 4. SCryptPasswordEncoder
     *
     * Algorithm: scrypt.
     *
     * Strengths:
     *
     * Memory-hard like Argon2 (harder to brute force with hardware).
     *
     * Adjustable cost parameters.
     *
     * Weaknesses:
     *
     * Less popular than Argon2, fewer libraries/tools support it.
     *
     * When to use:
     *
     * When you want memory-hard protection but don’t want Argon2.
     *
     * Legacy systems already using scrypt.
     *
     *
     * 5. NoOpPasswordEncoder (⚠️ Not Secure)
     *
     * Algorithm: None (plain text).
     *
     * When to use:
     *
     * Only for testing/demo environments.
     *
     * 🚫 Never use in production.
     *
     * | Encoder              | Security Level | Memory-Hard? | Performance | Best For                               |
     * | -------------------- | -------------- | ------------ | ----------- | -------------------------------------- |
     * | **BCrypt**           | High           | ❌            | Fast        | General apps (default)                 |
     * | **Argon2**           | Very High      | ✅            | Medium      | Modern, security-critical apps         |
     * | **PBKDF2**           | High           | ❌            | Medium      | Enterprise, compliance (NIST/FIPS)     |
     * | **scrypt**           | High           | ✅            | Slower      | Legacy systems needing memory-hardness |
     * | **NoOp**             | 🚫 None        | ❌            | Fastest     | Testing only                           |
     * | **SHA/MD5** (legacy) | 🚫 Weak        | ❌            | Fast        | Legacy only, should migrate            |
     */


