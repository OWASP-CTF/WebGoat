/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@RestController
public class MailAssignment implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  // Server-side single-use OTP store: username -> pending code (delivered only via email/WebWolf).
  private static final ConcurrentHashMap<String, String> pendingCodes = new ConcurrentHashMap<>();

  private final String webWolfURL;
  private RestTemplate restTemplate;

  public MailAssignment(
      RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
  }

  @PostMapping("/WebWolf/mail/send")
  @ResponseBody
  public AttackResult sendEmail(
      @RequestParam String email, @CurrentUsername String webGoatUsername) {
    String username = email.substring(0, email.indexOf("@"));
    if (username.equalsIgnoreCase(webGoatUsername)) {
      // SECURE: generate a random 128-bit code that is NOT derivable from the username; it is
      // stored server-side and only delivered out-of-band via the email retrieved in WebWolf.
      byte[] codeBytes = new byte[16];
      SECURE_RANDOM.nextBytes(codeBytes);
      String code = Base64.getUrlEncoder().withoutPadding().encodeToString(codeBytes);
      pendingCodes.put(username, code);

      Email mailEvent =
          Email.builder()
              .recipient(username)
              .title("Test messages from WebWolf")
              .contents("This is a test message from WebWolf, your unique code is: " + code)
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this)
            .feedback("webwolf.email_failed")
            .output(e.getMessage())
            .build();
      }
      return informationMessage(this).feedback("webwolf.email_send").feedbackArgs(email).build();
    } else {
      return informationMessage(this)
          .feedback("webwolf.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }

  @PostMapping("/WebWolf/mail")
  @ResponseBody
  public AttackResult completed(@RequestParam String uniqueCode, @CurrentUsername String username) {
    // SECURE: compare against the server-stored random code and consume it (single-use).
    String expected = pendingCodes.remove(username);
    if (expected != null
        && uniqueCode != null
        && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            uniqueCode.getBytes(StandardCharsets.UTF_8))) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("webwolf.code_incorrect").feedbackArgs(uniqueCode).build();
    }
  }
}
