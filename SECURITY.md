# Security policy

## Reporting

Use GitHub private vulnerability reporting for suspected security issues. Include the affected commit, reproduction steps, and whether the issue could cause RepoDoctor to execute target code, leak repository contents, expose an unredacted credential, or misclassify an unavailable lookup as safe.

Do not place live secrets or weaponized packages in a report. Synthetic fixtures are enough to demonstrate scanner behavior.

## Supported version

The current `main` branch is supported until tagged releases begin. Security fixes target the latest release and `main`.

## Intended boundary

RepoDoctor is designed to read untrusted repositories, but it is not a hardened sandbox. Run it as an unprivileged user. It does not install or execute target dependencies, and it limits file/HTTP sizes, but a defense-in-depth CI environment should still isolate repository scans.
