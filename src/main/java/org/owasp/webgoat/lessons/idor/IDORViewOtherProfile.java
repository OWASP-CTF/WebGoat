/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDORViewOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDORViewOtherProfile(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @GetMapping(
      path = "/IDOR/profile/{userId}",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(@PathVariable("userId") String userId) {

    Object obj = userSessionData.getValue("idor-authenticated-as");
    if (obj == null || !obj.equals("tom")) {
      return failed(this).build();
    }
    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // Horizontal access control (BOLA) fix: the authenticated user may ONLY access their
    // own profile. Any request for another user's id is rejected before the profile is
    // ever loaded, regardless of whether that id resolves to an existing record.
    if (userId == null || !userId.equals(authUserId)) {
      return failed(this).feedback("idor.view.profile.close1").build();
    }
    UserProfile requestedProfile = new UserProfile(userId);
    return success(this)
        .feedback("idor.view.profile.success")
        .output(requestedProfile.profileToMap().toString())
        .build();
  }
}
