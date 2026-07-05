<?php
/**
 * AI-tools token — short-lived RS256 assertion for the Nora widget chat.
 *
 * The Nora help drawer (inc/ai-help-drawer.php) iframes hjelp.nettsmed.no into
 * wp-admin. The iframe is cross-site, so no nettsmed.no cookie ever reaches it.
 * To let the widget chat call site-scoped read tools (wpadmin:// context on
 * hjelp.nettsmed.no), this parent page mints a narrow, single-use JWT on
 * request and hands it to the iframe via postMessage — never via a URL, never
 * cached client-side.
 *
 * Reuses the exact key-handling and signing mechanics of inc/minside-sso.php
 * (same MINSIDE_SSO_PRIVATE_KEY constant, same site_key, same raw-openssl
 * RS256 signer) with a different, narrower audience. Fail-closed: if the key
 * constant is absent, the token endpoint answers 503 and the drawer degrades
 * to KB-only — it never blocks wp-admin.
 *
 * @package NettsmedSupport
 */

declare( strict_types=1 );

namespace Nettsmed\AiToolsToken;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Constants ────────────────────────────────────────────────────────────────

// Distinct audience from the Min side SSO contract (NETTSMED_SSO_AUD) — this
// token is scoped to the AI tools surface only and carries no user identity.
const AI_TOOLS_AUD          = 'wp-ai-tools';
const AI_TOOLS_TTL_SECONDS  = 120;
const AJAX_ACTION           = 'nettsmed_ai_token';
const NONCE_ACTION          = 'nettsmed_ai_token';
const SCRIPT_HANDLE         = 'nettsmed-help-widget'; // enqueued by ai-help-drawer.php.

// ── Token minting ────────────────────────────────────────────────────────────

/**
 * Mint a short-lived RS256 JWT scoped to the AI tools audience.
 *
 * Claims: { iss, aud, site_key, iat, exp (+120s), jti }. No user identity —
 * the token proves which site the request runs on, nothing else.
 *
 * Sources the private key and site_key from inc/minside-sso.php's helpers
 * (same wp-config constants, same fail-closed behavior — no wp_option
 * fallback for the private key).
 *
 * @return string|\WP_Error JWT string, or WP_Error when unconfigured.
 */
function mint_token() {
	$private_pem = \Nettsmed\MinsideSSO\get_private_key_pem();
	if ( '' === $private_pem ) {
		return new \WP_Error( 'no_key', 'MINSIDE_SSO_PRIVATE_KEY is not defined.' );
	}

	$site_key = \Nettsmed\MinsideSSO\get_site_key();
	if ( '' === $site_key ) {
		return new \WP_Error( 'not_configured', 'Site key is not configured.' );
	}

	$private_key = openssl_pkey_get_private( $private_pem );
	if ( false === $private_key ) {
		return new \WP_Error( 'bad_key', 'Could not read the private key.' );
	}

	$now    = time();
	$header = array(
		'alg' => 'RS256',
		'typ' => 'JWT',
	);
	$payload = array(
		'iss'      => defined( 'NETTSMED_SSO_ISS' ) ? \NETTSMED_SSO_ISS : 'nettsmed-support-plugin',
		'aud'      => AI_TOOLS_AUD,
		'site_key' => $site_key,
		'iat'      => $now,
		'exp'      => $now + AI_TOOLS_TTL_SECONDS,
		'jti'      => bin2hex( random_bytes( 16 ) ),
	);

	$segments      = array(
		\Nettsmed\MinsideSSO\base64url_encode( (string) wp_json_encode( $header ) ),
		\Nettsmed\MinsideSSO\base64url_encode( (string) wp_json_encode( $payload ) ),
	);
	$signing_input = implode( '.', $segments );

	$signature = '';
	$ok        = openssl_sign( $signing_input, $signature, $private_key, OPENSSL_ALGO_SHA256 );
	if ( ! $ok ) {
		return new \WP_Error( 'sign_failed', 'Token signing failed.' );
	}

	$segments[] = \Nettsmed\MinsideSSO\base64url_encode( $signature );

	return implode( '.', $segments );
}

// ── admin-ajax endpoint ──────────────────────────────────────────────────────

/**
 * admin-ajax handler for `action=nettsmed_ai_token`.
 *
 * Gated the same way the drawer itself is (any logged-in wp-admin user —
 * see nettsmed_help_enqueue_drawer() in ai-help-drawer.php), plus a nonce.
 * Registered only under `wp_ajax_` (no `_nopriv_`), so logged-out requests
 * never reach the handler.
 *
 * Response on success: `{ "token": "<jwt>" }`. On failure: a non-2xx status
 * with an `error` code — never a stack trace, never the key material.
 *
 * @return void
 */
function handle_token_request() {
	check_ajax_referer( NONCE_ACTION, 'nonce' );

	$token = mint_token();
	if ( is_wp_error( $token ) ) {
		if ( class_exists( '\Sentry\SentrySdk' ) ) {
			\Sentry\captureMessage( 'nettsmed-ai-tools-token: mint_token failed — ' . $token->get_error_code() );
		}
		status_header( 503 );
		wp_send_json( array( 'error' => $token->get_error_code() ) );
	}

	wp_send_json( array( 'token' => $token ) );
}
add_action( 'wp_ajax_' . AJAX_ACTION, __NAMESPACE__ . '\\handle_token_request' );

// ── Parent-side postMessage bridge ──────────────────────────────────────────

/**
 * Enqueue the postMessage bridge that services token requests from the
 * drawer iframe (hjelp.nettsmed.no). Runs after ai-help-drawer.php's own
 * enqueue (priority 20 > 10) so SCRIPT_HANDLE is already registered; bails
 * if the help widget wasn't enqueued (e.g. user not logged in).
 *
 * Listens for `{ type: "nettsmed-wp-token-request" }` from the drawer,
 * validates both the message origin AND that the sender is an iframe on
 * this page whose src belongs to that origin (not just any postMessage
 * claiming to be from it), fetches a fresh token per request (never
 * cached), and replies with `{ type: "nettsmed-wp-token", token }` targeted
 * at that same origin. On ajax failure it replies with nothing — the
 * drawer's own timeout degrades it to KB-only.
 *
 * @return void
 */
function enqueue_bridge() {
	if ( ! is_user_logged_in() || ! wp_script_is( SCRIPT_HANDLE, 'enqueued' ) ) {
		return;
	}

	$cfg = array(
		'origin'  => untrailingslashit( defined( 'NETTSMED_HELP_BASE' ) ? \NETTSMED_HELP_BASE : 'https://hjelp.nettsmed.no' ),
		'ajaxUrl' => admin_url( 'admin-ajax.php' ),
		'action'  => AJAX_ACTION,
		'nonce'   => wp_create_nonce( NONCE_ACTION ),
	);

	$inline = 'window.__noraAiTools=' . wp_json_encode( $cfg ) . ';'
		. '(function(){var C=window.__noraAiTools;if(!C)return;'
		. 'function findDrawerIframe(src){'
		. 'var fs=document.querySelectorAll("iframe");'
		. 'for(var i=0;i<fs.length;i++){var f=fs[i];'
		. 'if(f.contentWindow===src&&f.src&&f.src.indexOf(C.origin)===0)return f;}'
		. 'return null;}'
		. 'window.addEventListener("message",function(e){'
		. 'if(e.origin!==C.origin)return;'
		. 'var d=e.data;if(!d||d.type!=="nettsmed-wp-token-request")return;'
		. 'if(!findDrawerIframe(e.source))return;'
		. 'var body=new URLSearchParams();body.set("action",C.action);body.set("nonce",C.nonce);'
		. 'fetch(C.ajaxUrl,{method:"POST",credentials:"same-origin",body:body}).then(function(r){'
		. 'if(!r.ok)throw new Error("token fetch failed");return r.json();'
		. '}).then(function(data){'
		. 'if(data&&data.token){e.source.postMessage({type:"nettsmed-wp-token",token:data.token},C.origin);}'
		. '}).catch(function(){});'
		. '});})();';

	wp_add_inline_script( SCRIPT_HANDLE, $inline, 'after' );
}
add_action( 'admin_enqueue_scripts', __NAMESPACE__ . '\\enqueue_bridge', 20 );
