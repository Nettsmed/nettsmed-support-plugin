<?php
// AUTO-GENERATED from @nettsmed/contracts — DO NOT EDIT.
// Run `pnpm gen:php` in the minside-nettsmed monorepo and re-commit this file.
if ( ! defined( 'NETTSMED_CONTRACTS_LOADED' ) ) {
	define( 'NETTSMED_CONTRACTS_LOADED', true );
	define( 'NETTSMED_SSO_ISS', 'nettsmed-support-plugin' );
	define( 'NETTSMED_SSO_AUD', 'minside.nettsmed.no' );
	define( 'NETTSMED_SSO_TTL', 90 );
	define( 'NETTSMED_HELP_BASE', 'https://hjelp.nettsmed.no' );
	define( 'NETTSMED_PM_EVENT', 'nettsmed-open-minside' );
	// AI-read callback pubkey (Ledd 3, ai-read-consent.php): minside's dedicated
	// AI_CALLBACK_ED25519_PRIVATE_PEM signs; this is its public half (base64,
	// raw 32-byte Ed25519 — not PEM). Added ahead of WP2's packages/contracts
	// render-template regen (2026-07-06) — value is final, not placeholder.
	define( 'NETTSMED_AI_CALLBACK_PUBKEY', '3og6aAFl6SN2x3qdmzIaC5k1ayzpTCwD0DI5QGIIC98=' );
	$GLOBALS['NETTSMED_HELP_STACKS'] = [ 'elementor', 'gutenberg', 'woocommerce', 'wordpress', 'generell' ];
	$GLOBALS['NETTSMED_HELP_STACK_LABELS'] = [
    'elementor' => 'Elementor',
    'gutenberg' => 'Gutenberg',
    'woocommerce' => 'WooCommerce',
    'wordpress' => 'WordPress',
    'generell' => 'Generelt'
	];
	$GLOBALS['NETTSMED_OPEN_NEXT_PATHS'] = [ '', '/drift', '/faktura', '/support' ];
	$GLOBALS['NETTSMED_HELP_ARTICLE_SLUGS'] = [
    'wordpress/introduksjon',
    'wordpress/side-vs-innlegg',
    'wordpress/publisering',
    'wordpress/endre-lenker',
    'wordpress/lokal-nettleser',
    'wordpress/logge-inn',
    'wordpress/glemt-passord',
    'wordpress/nye-brukere',
    'wordpress/gutenberg',
    'elementor/introduksjon',
    'sikkerhet/tofaktor'
	];
}
