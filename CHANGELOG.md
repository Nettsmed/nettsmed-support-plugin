# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
