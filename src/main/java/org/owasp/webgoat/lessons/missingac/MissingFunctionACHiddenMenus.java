/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 1/5/17. */
@RestController
@AssignmentHints({
  "access-control.hidden-menus.hint1",
  "access-control.hidden-menus.hint2",
  "access-control.hidden-menus.hint3"
})
public class MissingFunctionACHiddenMenus implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACHiddenMenus(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/hidden-menu",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      @CurrentUsername String username, String hiddenMenu1, String hiddenMenu2) {
    // Function-level access control: the hidden admin menu is privileged functionality. Verify the
    // authenticated caller is actually an admin server-side before honoring the request. Hiding
    // menu items in the UI is not a security control, so a non-admin (or unknown) user is rejected.
    var currentUser = userRepository.findByUsername(username);
    if (currentUser == null || !currentUser.isAdmin()) {
      return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
    }
    if (hiddenMenu1.equals("Users") && hiddenMenu2.equals("Config")) {
      return success(this).output("").feedback("access-control.hidden-menus.success").build();
    }

    if (hiddenMenu1.equals("Config") && hiddenMenu2.equals("Users")) {
      return failed(this).output("").feedback("access-control.hidden-menus.close").build();
    }

    return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
  }
}
