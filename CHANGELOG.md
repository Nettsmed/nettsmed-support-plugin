# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.8.0] - 2026-06-30

### Removed

- Floating launcher (the branded blue help/«Kontakt oss» bubble,
  `#minside-launcher` on `wp_footer`) from `inc/minside-sso.php`. Frontend help
  and contact are now consolidated into the Nora assistant; in wp-admin, Min
  side lives in the Nora help drawer. (TSK-19103)
- Launcher-only helper `support_email()` and the `minside_accent_color` /
  `minside_support_email` filters (now unused).

### Unchanged

- SSO mint, SP-initiated flow, sidebar springboard, admin-bar shortcut and
  `launch_url()` are untouched.

## [1.7.1] - 2026-06-26

### Changed

- Min side launch (`launch_url`) now routes through minside's SP-initiated
  `/sso/start?domain=&return=` instead of the local nonce-protected admin-post
  mint. The "Min side" button now traverses the same CSRF-state-protected flow as
  the `/login` path, so it keeps working when minside enforces `SSO_V2_ENABLED`
  (the old `state=''` admin-post mint would be rejected under V2). The admin-post
  handler is retained for backward compatibility but no longer used by the button.

## [1.7.0] - 2026-06-26

### Removed

- `fjellestad-support-backend-widget.php` — BetterDocs cross-domain chat widget
  (hardcoded nettsmed.no docs; superseded by Nora).
- `custom-dashboard.php` + `assets/css/my-custom-dashboard.css` +
  `assets/html/my-custom-dashboard-content.html` — "Brukerveiledning" wp-admin
  menu page with static HTML content (superseded by Nora).
- `add_dynamic_menu_for_users()`, `display_embed_page()`, `add_embed_page_script()`
  from `inc/admin-dashboard-settings.php` — configurable embed-code widget that
  exposed arbitrary iframe content via wp-options (superseded by Nora).
- `admin_dashboard_embed_code` and `admin_dashboard_menu_title` settings entries
  and their form fields from the Dashboard Settings page.

### Fixed

- `redirect_to_custom_dashboard()` in `simpel-admin-role.php` now redirects
  non-admin users to `index.php` instead of the removed `brukerveiledning` page.

## [1.6.0] - 2026-06-26

### Added

- Min side SSO (inc/minside-sso.php): hardened JWT minting — aud claim set to
  `minside.nettsmed.no`, exp=iat+90s, jti=bin2hex(random_bytes(16)) CSPRNG,
  state claim echoes SP-initiated state for CSRF protection.
- SP-initiated flow: `?minside_sso=start&state=X&return=/path` handler reads and
  forwards state inside the assertion; preserves state+return on WP-login bounce.
- emit_sso_post: Cache-Control no-store/no-cache/private + nocache_headers() +
  DONOTCACHEPAGE — prevents page caches from serving the SSO form.
- Fail-closed key loading: MINSIDE_SSO_PRIVATE_KEY must be defined as a
  wp-config.php constant; no wp_option fallback. If absent, admin-notice is shown
  and Sentry is notified on attempted mint.
- MINSIDE_SSO_AUTOBOUNCE constant defaulting to false (auto-bounce disabled).

### Removed

- Private key wp_option fallback (minside_sso_private_key option) — constant-only
  going forward. Existing option values in the DB are ignored and can be deleted.
- Settings-page private key textarea — replaced by constant-status indicator.

## [1.5.0]

### Added

- Min side integration in the Nora drawer. When the minside-SSO bridge plugin is
  present and configured, the drawer shows a «Min side»-section in its top bar
  (Åpne Min side + Trafikk & drift / Fakturaer / Support-saker + Kontakt oss).
  Clicking a link postMessages this parent page, which opens the matching
  minside-SSO launch URL (token minted server-side; origin-validated against the
  hjelp.nettsmed.no iframe). This replaces the separate floating «Åpne Min side»
  launcher so wp-admin has a single widget — Nora.

## [1.4.0]

### Added

- Nora — context-aware AI help drawer in wp-admin. Enqueues the shared Nettsmed
  chat widget from hjelp.nettsmed.no across admin pages, passing the current
  screen id and detected stack (WooCommerce / Elementor / Gutenberg / WordPress)
  so the drawer surfaces screen-aware suggestions and weights its answers. Help
  content is public, so no auth/token crosses the iframe. New `inc/ai-help-drawer.php`;
  help center base overridable via the `NETTSMED_HELP_BASE` constant.

## [1.3.1]

### Fixed

- Include vendor/ in repository so Kernl-distributed zip contains Composer dependencies

## [1.3.0]

### Added

- Sentry error reporting integration for plugin-scoped error monitoring

### Changed

- Hardcode Sentry DSN in plugin — no longer requires wp-config.php constant

## [1.2.5]

### Changed

- Extended 2FA bypass to include Editor, Author and Contributor roles

## [1.2.4]

### Fixed

- Analytics menu field no longer accessible when Plausible plugin is inactive

## [1.2.3]

### Fixed

- Editors now have view access to Analytics (Plausible)

## [1.2.2]

### Added

- Plausible analytics as "Analyse" page

## [1.2.1]

### Added

- Security toggle for disabling 2FA for simple admins

## [1.2.0]

### Added

- Embed help doc for site-specific helpdesk documentation
- Nettsmed Admin dashboard in WordPress backend

## [1.1.8]

### Changed

- Hide additional backend pages for simple admin role

## [1.1.7]

### Changed

- Optimized backend widget
- White label edits for Nettsmed
