/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint1", "ssrf.hint2"})
public class SSRFTask1 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task1")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return stealTheCheese(url);
  }

  // SECURE: the server owns every retrievable resource. The client-supplied value is treated as
  // an opaque key mapped to a fixed, application-controlled path — it can no longer name an
  // arbitrary resource, so substituting "images/jerry.png" is not honored.
  private static final java.util.Map<String, String> ALLOWED_IMAGES =
      java.util.Map.of("profile", "images/tom.png");

  protected AttackResult stealTheCheese(String url) {
    try {
      String resource = ALLOWED_IMAGES.get(url);
      if (resource == null) {
        // Not an approved identifier (including any client-supplied path such as jerry.png).
        String html = "<img class=\"image\" alt=\"Silly Cat\" src=\"images/cat.jpg\">";
        return failed(this).feedback("ssrf.failure").output(html).build();
      }
      String html =
          "<img class=\"image\" alt=\"Tom\" src=\""
              + resource
              + "\" width=\"25%\" height=\"25%\">";
      return failed(this).feedback("ssrf.tom").output(html).build();
    } catch (Exception e) {
      return failed(this).output(e.getMessage()).build();
    }
  }
}
