/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.ownProfileAltUrl1",
  "idor.hints.ownProfileAltUrl2",
  "idor.hints.ownProfileAltUrl3"
})
public class IDORViewOwnProfileAltUrl implements AssignmentEndpoint {
  private final LessonSession userSessionData;

  public IDORViewOwnProfileAltUrl(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping("/IDOR/profile/alt-path")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    // Never parse or trust the client-supplied URL to resolve a server-side resource.
    // The only authoritative source of identity is the server-side session.
    Object authenticatedAs = userSessionData.getValue("idor-authenticated-as");
    if (!"tom".equals(authenticatedAs)) {
      return failed(this).feedback("idor.view.own.profile.failure2").build();
    }

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null || authUserId.isBlank()) {
      return failed(this).feedback("idor.view.own.profile.failure1").build();
    }

    // Resolve the profile from the authenticated identity, not from the request 'url'.
    UserProfile userProfile = new UserProfile(authUserId);
    return success(this)
        .feedback("idor.view.own.profile.success")
        .output(userProfile.profileToMap().toString())
        .build();
  }
}
