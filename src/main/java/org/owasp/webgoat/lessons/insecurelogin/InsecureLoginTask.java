/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final String USERNAME = "CaptainJack";

  // No hard-coded credentials: the account password is a high-entropy secret generated with a
  // CSPRNG at startup and retained only as a salted adaptive (BCrypt) hash. It is never a source
  // literal and is not exposed by any endpoint, so credentials recovered from the (formerly
  // plaintext) login traffic can no longer be replayed to authenticate.
  private final PasswordEncoder encoder = new BCryptPasswordEncoder();
  private final String passwordHash;

  public InsecureLoginTask() {
    byte[] secret = new byte[24];
    new SecureRandom().nextBytes(secret);
    String password = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    this.passwordHash = encoder.encode(password);
  }

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    // Constant-time verification against the stored salted hash.
    if (USERNAME.equals(username) && encoder.matches(password, passwordHash)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login() {
    // only need to exists as the JS needs to call an existing endpoint
  }
}
