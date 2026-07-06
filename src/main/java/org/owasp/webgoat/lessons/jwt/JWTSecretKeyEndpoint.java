/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  public static final String[] SECRETS = {
    "victory", "business", "available", "shipping", "washington"
  };

  // SECURITY FIX (JWT weak-secret cracking): the HS256 signing key must be a high-entropy,
  // cryptographically-random value generated at startup with SecureRandom — never a
  // base64-encoded dictionary word (which is brute-forceable offline in microseconds).
  public static final String JWT_SECRET = generateSigningKey();

  private static String generateSigningKey() {
    byte[] keyBytes = new byte[32]; // 256-bit HMAC key
    new SecureRandom().nextBytes(keyBytes);
    return Base64.getEncoder().encodeToString(keyBytes);
  }
  private static final String WEBGOAT_USER = "WebGoat";
  private static final List<String> expectedClaims =
      List.of("iss", "iat", "exp", "aud", "sub", "username", "Email", "Role");

  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return Jwts.builder()
        .setIssuer("WebGoat Token Builder")
        .setAudience("webgoat.org")
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject("tom@webgoat.org")
        .claim("username", "Tom")
        .claim("Email", "tom@webgoat.org")
        .claim("Role", new String[] {"Manager", "Project Administrator"})
        .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
        .compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token);
      Claims claims = (Claims) jwt.getBody();
      if (!claims.keySet().containsAll(expectedClaims)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      } else {
        String user = (String) claims.get("username");

        if (WEBGOAT_USER.equalsIgnoreCase(user)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
        }
      }
    } catch (Exception e) {
      return failed(this).feedback("jwt-invalid-token").output(e.getMessage()).build();
    }
  }
}
