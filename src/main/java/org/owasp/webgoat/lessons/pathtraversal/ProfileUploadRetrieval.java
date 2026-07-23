/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {
  private final File catPicturesDirectory;

  // Unpredictable, server-generated secret. It is NOT derived from any attacker-known value
  // (such as the username), so it cannot be computed offline.
  private final String secretToken = UUID.randomUUID().toString();

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory = new File(webGoatHomeDirectory, "/PathTraversal/" + "/cats");
    this.catPicturesDirectory.mkdirs();
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
    var secretDirectory = this.catPicturesDirectory.getParentFile().getParentFile();
    try {
      // The secret written to disk is the unpredictable server token, not an instruction to
      // compute a deterministic hash of a known value.
      Files.writeString(
          secretDirectory.toPath().resolve("path-traversal-secret.jpg"), secretToken);
    } catch (IOException e) {
      log.error("Unable to write secret in: {}", secretDirectory, e);
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "secret", required = false) String secret,
      @CurrentUsername String username) {
    // Compare against the unpredictable server-side token using a constant-time comparison.
    // The secret can no longer be derived from the (attacker-known) username.
    if (secret != null
        && MessageDigest.isEqual(
            secretToken.getBytes(StandardCharsets.UTF_8),
            secret.getBytes(StandardCharsets.UTF_8))) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    var id = request.getParameter("id");

    // Accept only a numeric picture id within the valid range. Any non-numeric input is
    // rejected outright, so a path such as "../path-traversal-secret" can never be
    // constructed from user input.
    int pictureId;
    try {
      pictureId = (id == null) ? RandomUtils.nextInt(1, 11) : Integer.parseInt(id.trim());
    } catch (NumberFormatException e) {
      return ResponseEntity.badRequest().build();
    }
    if (pictureId < 1 || pictureId > 10) {
      return ResponseEntity.badRequest().build();
    }

    try {
      var catPicture = new File(catPicturesDirectory, pictureId + ".jpg");

      // Defense-in-depth: canonical-path containment ensures the resolved file cannot escape
      // the cats directory.
      String canonicalDir = catPicturesDirectory.getCanonicalPath();
      if (!catPicture.getCanonicalPath().startsWith(canonicalDir + File.separator)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
      }

      if (catPicture.exists()) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .location(new URI("/PathTraversal/random-picture?id=" + pictureId))
            .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
      }
      return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }

    return ResponseEntity.badRequest().build();
  }
}
