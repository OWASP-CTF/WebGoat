/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // Horizontal access control (BOLA) fix: the caller may only edit their OWN profile.
    // The userId path variable is validated against the authenticated principal before any
    // mutation occurs; requests targeting another user's id are rejected outright.
    if (authUserId == null || userId == null || !userId.equals(authUserId)) {
      return failed(this).feedback("idor.edit.profile.failure3").build();
    }

    UserProfile currentUserProfile = new UserProfile(userId);
    // Mass-assignment protection: privileged fields (role, isAdmin, userId) are NEVER read
    // from the client payload. Only user-editable fields are applied server-side.
    if (userSubmittedProfile.getColor() != null) {
      currentUserProfile.setColor(userSubmittedProfile.getColor());
    }
    if (userSubmittedProfile.getSize() != null) {
      currentUserProfile.setSize(userSubmittedProfile.getSize());
    }
    userSessionData.setValue("idor-updated-other-profile", currentUserProfile);
    return failed(this).feedback("idor.edit.profile.failure3").build();
  }
}
