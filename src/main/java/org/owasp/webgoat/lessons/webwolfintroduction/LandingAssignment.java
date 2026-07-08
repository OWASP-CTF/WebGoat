/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class LandingAssignment implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  // Per-user nonce: issued when the landing page is opened, consumed on POST.
  private static final ConcurrentHashMap<String, String> issuedCodes = new ConcurrentHashMap<>();

  private final String landingPageUrl;

  public LandingAssignment(@Value("${webwolf.landingpage.url}") String landingPageUrl) {
    this.landingPageUrl = landingPageUrl;
  }

  @PostMapping("/WebWolf/landing")
  @ResponseBody
  public AttackResult click(String uniqueCode, @CurrentUsername String username) {
    // SECURE: compare against the server-stored random nonce (not a value derivable from the
    // username), then consume it so it cannot be replayed.
    String expected = issuedCodes.remove(username);
    if (expected != null
        && uniqueCode != null
        && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            uniqueCode.getBytes(StandardCharsets.UTF_8))) {
      return success(this).build();
    }
    return failed(this).feedback("webwolf.landing_wrong").build();
  }

  @GetMapping("/WebWolf/landing/password-reset")
  public ModelAndView openPasswordReset(@CurrentUsername String username) {
    // SECURE: generate a high-entropy nonce and deliver it only via the out-of-band WebWolf
    // landing callback URL — never render it into the page returned to the browser.
    byte[] tokenBytes = new byte[16];
    SECURE_RANDOM.nextBytes(tokenBytes);
    String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    issuedCodes.put(username, nonce);

    ModelAndView modelAndView = new ModelAndView();
    modelAndView.addObject(
        "webwolfLandingPageUrl",
        landingPageUrl.replace("//landing", "/landing") + "?code=" + nonce);
    modelAndView.setViewName("lessons/webwolfintroduction/templates/webwolfPasswordReset.html");
    return modelAndView;
  }
}
