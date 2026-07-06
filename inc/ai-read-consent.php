<?php
/**
 * Self-serve AI-read consent + signed read route for the Nora chat widget.
 *
 * Extends TSK-19168 with Model B (design doc: nettsmed-kundestotte's
 * docs/superpowers/specs/2026-07-06-ai-read-consent-design.md). Drops the
 * app-password credential entirely — the site's own SSO key pair already
 * proves site↔tenant trust, so this file adds two new signed legs on top of
 * it instead:
 *
 * Ledd 2 (consent ping, plugin -> minside): when an admin toggles "La Spør
 * AI lese nettstedet" in wp-admin, mint_consent_token() mints a short-lived
 * RS256 JWT (reusing minside-sso.php's private-key + site_key helpers, same
 * mechanics as ai-tools-token.php's mint_token()) and send_consent_ping()
 * POSTs it to minside so `tenant_sites.ai_read_enabled` stays in sync.
 *
 * Ledd 3 (signed read callback, minside -> plugin): registers
 * nettsmed/v1/ai/{posts,pages,post-types,post}, a narrow read-only REST
 * surface gated on an EdDSA-signed bearer assertion from minside
 * (verify_callback_request(), via sodium_crypto_sign_verify_detached against
 * NETTSMED_AI_CALLBACK_PUBKEY) plus the local consent flag. Fail-closed: any
 * verification failure or consent-off returns the same generic 403 — never
 * leaks which check failed. Responses are curated, published-only
 * projections built from native get_posts()/get_post_types() — never raw WP
 * data, drafts, private posts, or user data.
 *
 * @package NettsmedSupport
 */

declare( strict_types=1 );

namespace Nettsmed\AiReadConsent;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Same vendored, auto-generated contract file minside-sso.php requires. It now
// carries NETTSMED_AI_CALLBACK_PUBKEY, generated from packages/contracts on the
// minside side — the single source of truth for the callback public key.
require_once __DIR__ . '/contracts.generated.php';

// ── Constants ────────────────────────────────────────────────────────────────

const OPTION_ENABLED      = 'nettsmed_ai_read_enabled';
const REQUIRED_CAPABILITY = 'manage_options';
const SETTINGS_SLUG       = 'nettsmed-ai-read';
const ADMIN_POST_ACTION   = 'nettsmed_ai_consent_toggle';
const NONCE_ACTION        = 'nettsmed_ai_consent_toggle';

// Ledd 2 — consent ping (plugin -> minside).
const CONSENT_AUD         = 'nettsmed-ai-consent';
const CONSENT_TTL_SECONDS = 120;
const CONSENT_ENDPOINT    = '/api/ai/wp/consent';

// Ledd 3 — signed read callback (minside -> plugin).
const CALLBACK_ISS        = 'nettsmed-minside';
const CALLBACK_AUD        = 'nettsmed-ai-callback';
const CALLBACK_ALG        = 'EdDSA';
const CALLBACK_SKEW       = 30; // Seconds of clock-skew grace around exp/iat.
const REST_NAMESPACE      = 'nettsmed/v1';
const MAX_PER_PAGE        = 10;
const EXCERPT_MAX_LENGTH  = 300;

// ── Consent state ────────────────────────────────────────────────────────────

/**
 * Is AI-read consent currently on for this site?
 */
function is_enabled(): bool {
	return (bool) get_option( OPTION_ENABLED, false );
}

// ── Ledd 2: consent-mint + ping ──────────────────────────────────────────────

/**
 * Mint a short-lived RS256 JWT carrying the desired consent state.
 *
 * Claims: { iss, aud, site_key, enabled, iat, exp (+120s), jti }.
 *
 * SECURITY: no `sub` claim — same invariant as ai-tools-token.php's
 * mint_token(): this token proves which site is toggling consent, never who
 * toggled it, so it can never be mistaken for a login assertion by minside's
 * legacy (V2=off) SSO path.
 *
 * @param bool $enabled Desired nettsmed_ai_read_enabled state.
 * @return string|\WP_Error JWT string, or WP_Error when unconfigured.
 */
function mint_consent_token( bool $enabled ) {
	$private_pem = \Nettsmed\MinsideSSO\get_private_key_pem();
	if ( '' === $private_pem ) {
		return new \WP_Error( 'no_key', __( 'MINSIDE_SSO_PRIVATE_KEY er ikke definert.', 'nettsmed-support' ) );
	}

	$site_key = \Nettsmed\MinsideSSO\get_site_key();
	if ( '' === $site_key ) {
		return new \WP_Error( 'not_configured', __( 'Site key er ikke konfigurert.', 'nettsmed-support' ) );
	}

	$private_key = openssl_pkey_get_private( $private_pem );
	if ( false === $private_key ) {
		return new \WP_Error( 'bad_key', __( 'Kunne ikke lese den private nøkkelen.', 'nettsmed-support' ) );
	}

	$now    = time();
	$header = array(
		'alg' => 'RS256',
		'typ' => 'JWT',
	);

	$payload = array(
		'iss'      => defined( 'NETTSMED_SSO_ISS' ) ? \NETTSMED_SSO_ISS : 'nettsmed-support-plugin',
		'aud'      => CONSENT_AUD,
		'site_key' => $site_key,
		'enabled'  => $enabled,
		'iat'      => $now,
		'exp'      => $now + CONSENT_TTL_SECONDS,
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
		return new \WP_Error( 'sign_failed', __( 'Signering av token feilet.', 'nettsmed-support' ) );
	}

	$segments[] = \Nettsmed\MinsideSSO\base64url_encode( $signature );

	return implode( '.', $segments );
}

/**
 * POST the consent token to minside.
 *
 * Never blocks the local toggle — the caller updates `nettsmed_ai_read_enabled`
 * regardless of this call's outcome and surfaces failures via an admin notice
 * so it can be retried; the plugin's own gate (is_enabled()) is authoritative
 * for the read route either way.
 *
 * @param string $token Signed consent JWT.
 * @return true|\WP_Error True on a 200 response, WP_Error otherwise.
 */
function send_consent_ping( string $token ) {
	$endpoint = \Nettsmed\MinsideSSO\minside_url() . CONSENT_ENDPOINT;

	$response = wp_remote_post(
		$endpoint,
		array(
			'timeout' => 8,
			'headers' => array( 'Content-Type' => 'application/json' ),
			'body'    => wp_json_encode( array( 'token' => $token ) ),
		)
	);

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$code = wp_remote_retrieve_response_code( $response );
	if ( 200 !== $code ) {
		return new \WP_Error( 'consent_ping_failed', sprintf( 'minside svarte %d.', $code ) );
	}

	return true;
}

// ── wp-admin settings page ───────────────────────────────────────────────────

/**
 * Register «Spør AI» under Settings — always visible so an unconfigured
 * site can still show the "ikke koblet til Min side" state.
 */
function add_settings_page(): void {
	add_options_page(
		__( 'Spør AI', 'nettsmed-support' ),
		__( 'Spør AI', 'nettsmed-support' ),
		REQUIRED_CAPABILITY,
		SETTINGS_SLUG,
		__NAMESPACE__ . '\\render_settings_page'
	);
}
add_action( 'admin_menu', __NAMESPACE__ . '\\add_settings_page' );

/**
 * Render one of the fixed admin-post redirect notices.
 */
function render_notice( string $code ): void {
	$notices = array(
		'ok'             => array( 'success', __( 'Lagret. Min side er varslet.', 'nettsmed-support' ) ),
		'ping_failed'    => array( 'warning', __( 'Lagret lokalt, men Min side kunne ikke varsles akkurat nå. Endringen er likevel aktiv på dette nettstedet.', 'nettsmed-support' ) ),
		'not_configured' => array( 'error', __( 'Min side-SSO er ikke konfigurert på dette nettstedet.', 'nettsmed-support' ) ),
	);
	if ( ! isset( $notices[ $code ] ) ) {
		return;
	}
	list( $type, $message ) = $notices[ $code ];
	printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $type ), esc_html( $message ) );
}

function render_settings_page(): void {
	if ( ! current_user_can( REQUIRED_CAPABILITY ) ) {
		wp_die( esc_html__( 'Ingen tilgang.', 'nettsmed-support' ) );
	}

	$configured = \Nettsmed\MinsideSSO\is_configured();
	$enabled    = is_enabled();

	echo '<div class="wrap">';
	echo '<h1>' . esc_html__( 'Spør AI', 'nettsmed-support' ) . '</h1>';
	echo '<p style="font-size:14px;max-width:60ch">' . esc_html__( 'La Spør AI lese nettstedet', 'nettsmed-support' ) . '</p>';
	echo '<p class="description" style="max-width:60ch">'
		. esc_html__( 'Kun lesing. Ingen passord. Du kan skru det av når som helst.', 'nettsmed-support' )
		. '</p>';

	if ( isset( $_GET['nettsmed_ai_notice'] ) ) {
		render_notice( sanitize_key( wp_unslash( $_GET['nettsmed_ai_notice'] ) ) );
	}

	if ( ! $configured ) {
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html__( 'Ikke koblet til Min side. Konfigurer Min side-SSO (MINSIDE_SSO_PRIVATE_KEY og site key) før du kan skru på AI-lesing.', 'nettsmed-support' )
		);
		printf(
			'<p><strong>%s</strong> %s</p><p><button type="button" class="button" disabled>%s</button></p>',
			esc_html__( 'Status:', 'nettsmed-support' ),
			esc_html( $enabled ? __( 'På', 'nettsmed-support' ) : __( 'Av', 'nettsmed-support' ) ),
			esc_html( $enabled ? __( 'Skru av', 'nettsmed-support' ) : __( 'Skru på', 'nettsmed-support' ) )
		);
		echo '</div>';
		return;
	}

	printf(
		'<p><strong>%s</strong> %s</p>',
		esc_html__( 'Status:', 'nettsmed-support' ),
		$enabled
			? '<span style="color:#00a32a;font-weight:600">' . esc_html__( 'På', 'nettsmed-support' ) . '</span>'
			: '<span style="color:#646970;font-weight:600">' . esc_html__( 'Av', 'nettsmed-support' ) . '</span>'
	);

	echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
	wp_nonce_field( NONCE_ACTION );
	echo '<input type="hidden" name="action" value="' . esc_attr( ADMIN_POST_ACTION ) . '" />';
	echo '<input type="hidden" name="enabled" value="' . ( $enabled ? '0' : '1' ) . '" />';
	printf(
		'<button type="submit" class="button button-primary">%s</button>',
		esc_html( $enabled ? __( 'Skru av', 'nettsmed-support' ) : __( 'Skru på', 'nettsmed-support' ) )
	);
	echo '</form>';

	echo '</div>';
}

// ── admin-post handler ───────────────────────────────────────────────────────

/**
 * Redirect back to the settings page carrying a fixed notice code, then exit.
 */
function redirect_with_notice( string $code ): void {
	$url = add_query_arg(
		array(
			'page'               => SETTINGS_SLUG,
			'nettsmed_ai_notice' => $code,
		),
		admin_url( 'options-general.php' )
	);
	wp_safe_redirect( $url );
	exit;
}

/**
 * Toggle handler: capability + nonce, flip the local option, mint + POST the
 * Ledd 2 consent token. The local option is authoritative for the read route
 * regardless of whether minside could be reached.
 */
function handle_toggle(): void {
	if ( ! current_user_can( REQUIRED_CAPABILITY ) ) {
		wp_die( esc_html__( 'Ingen tilgang.', 'nettsmed-support' ), 403 );
	}

	check_admin_referer( NONCE_ACTION );

	if ( ! \Nettsmed\MinsideSSO\is_configured() ) {
		redirect_with_notice( 'not_configured' );
	}

	$enabled = isset( $_POST['enabled'] ) && '1' === $_POST['enabled'];

	update_option( OPTION_ENABLED, $enabled );

	$token = mint_consent_token( $enabled );
	if ( is_wp_error( $token ) ) {
		if ( class_exists( '\Sentry\SentrySdk' ) ) {
			\Sentry\captureMessage( 'nettsmed-ai-read-consent: mint failed — ' . $token->get_error_code() );
		}
		redirect_with_notice( 'ping_failed' );
	}

	$sent = send_consent_ping( $token );
	if ( is_wp_error( $sent ) ) {
		if ( class_exists( '\Sentry\SentrySdk' ) ) {
			\Sentry\captureMessage( 'nettsmed-ai-read-consent: ping failed — ' . $sent->get_error_code() );
		}
		redirect_with_notice( 'ping_failed' );
	}

	redirect_with_notice( 'ok' );
}
add_action( 'admin_post_' . ADMIN_POST_ACTION, __NAMESPACE__ . '\\handle_toggle' );

// ── Ledd 3: signed read route ────────────────────────────────────────────────

/**
 * Base64url-decode (RFC 7515) — accepts unpadded input.
 *
 * minside-sso.php only exports the encode direction; this file needs decode
 * to parse the inbound EdDSA assertion, so it gets its own small helper
 * rather than modifying that file.
 *
 * @return string|false Decoded bytes, or false on malformed input.
 */
function base64url_decode( string $data ) {
	$remainder = strlen( $data ) % 4;
	if ( 0 !== $remainder ) {
		$data .= str_repeat( '=', 4 - $remainder );
	}
	return base64_decode( strtr( $data, '-_', '+/' ), true );
}

/**
 * REST permission_callback for the nettsmed/v1/ai/* routes.
 *
 * Verifies the EdDSA bearer assertion from minside (Ledd 3): parses the JWT,
 * rejects anything with alg != EdDSA (no alg-confusion), verifies the
 * signature with sodium_crypto_sign_verify_detached against
 * NETTSMED_AI_CALLBACK_PUBKEY, checks iss/aud/exp/iat/site_key, and requires
 * the local consent flag to be on. Any failure returns the same generic
 * 403 — never leaks which check failed.
 *
 * @param \WP_REST_Request $request Incoming REST request.
 * @return true|\WP_Error
 */
function verify_callback_request( \WP_REST_Request $request ) {
	$forbidden = static function () {
		return new \WP_Error( 'nettsmed_ai_forbidden', 'Forbidden.', array( 'status' => 403 ) );
	};

	if ( ! is_enabled() ) {
		return $forbidden();
	}

	if ( ! defined( 'NETTSMED_AI_CALLBACK_PUBKEY' ) || '' === (string) \NETTSMED_AI_CALLBACK_PUBKEY ) {
		return $forbidden();
	}

	$auth = (string) $request->get_header( 'authorization' );
	if ( 0 !== strpos( $auth, 'Bearer ' ) ) {
		return $forbidden();
	}
	$jwt = trim( substr( $auth, 7 ) );

	$parts = explode( '.', $jwt );
	if ( 3 !== count( $parts ) ) {
		return $forbidden();
	}
	list( $header_b64, $payload_b64, $sig_b64 ) = $parts;

	$header_raw  = base64url_decode( $header_b64 );
	$payload_raw = base64url_decode( $payload_b64 );
	$sig_raw     = base64url_decode( $sig_b64 );
	if ( false === $header_raw || false === $payload_raw || false === $sig_raw ) {
		return $forbidden();
	}

	$header  = json_decode( $header_raw, true );
	$payload = json_decode( $payload_raw, true );
	if ( ! is_array( $header ) || ! is_array( $payload ) ) {
		return $forbidden();
	}

	if ( ! isset( $header['alg'] ) || CALLBACK_ALG !== $header['alg'] ) {
		return $forbidden();
	}

	$pubkey_raw = base64_decode( (string) \NETTSMED_AI_CALLBACK_PUBKEY, true );
	if ( false === $pubkey_raw || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pubkey_raw ) ) {
		return $forbidden();
	}

	$signing_input = $header_b64 . '.' . $payload_b64;
	if ( ! sodium_crypto_sign_verify_detached( $sig_raw, $signing_input, $pubkey_raw ) ) {
		return $forbidden();
	}

	$now = time();
	if ( ! isset( $payload['iss'] ) || CALLBACK_ISS !== $payload['iss'] ) {
		return $forbidden();
	}
	if ( ! isset( $payload['aud'] ) || CALLBACK_AUD !== $payload['aud'] ) {
		return $forbidden();
	}
	if ( ! isset( $payload['exp'] ) || ( $now - CALLBACK_SKEW ) > (int) $payload['exp'] ) {
		return $forbidden();
	}
	if ( ! isset( $payload['iat'] ) || (int) $payload['iat'] > ( $now + CALLBACK_SKEW ) ) {
		return $forbidden();
	}

	$site_key = \Nettsmed\MinsideSSO\get_site_key();
	if ( '' === $site_key || ! isset( $payload['site_key'] ) || ! hash_equals( $site_key, (string) $payload['site_key'] ) ) {
		return $forbidden();
	}

	return true;
}

/**
 * Shared args schema for the list routes (posts/pages).
 */
function list_args(): array {
	return array(
		'perPage' => array(
			'type'              => 'integer',
			'sanitize_callback' => 'absint',
		),
		'search'  => array(
			'type'              => 'string',
			'sanitize_callback' => 'sanitize_text_field',
		),
	);
}

function register_routes(): void {
	$common = array(
		'methods'             => \WP_REST_Server::READABLE,
		'permission_callback' => __NAMESPACE__ . '\\verify_callback_request',
	);

	register_rest_route(
		REST_NAMESPACE,
		'/ai/posts',
		array_merge( $common, array( 'callback' => __NAMESPACE__ . '\\handle_posts', 'args' => list_args() ) )
	);
	register_rest_route(
		REST_NAMESPACE,
		'/ai/pages',
		array_merge( $common, array( 'callback' => __NAMESPACE__ . '\\handle_pages', 'args' => list_args() ) )
	);
	register_rest_route(
		REST_NAMESPACE,
		'/ai/post-types',
		array_merge( $common, array( 'callback' => __NAMESPACE__ . '\\handle_post_types' ) )
	);
	register_rest_route(
		REST_NAMESPACE,
		'/ai/post',
		array_merge(
			$common,
			array(
				'callback' => __NAMESPACE__ . '\\handle_post',
				'args'     => array(
					'id' => array(
						'required'          => true,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
					),
				),
			)
		)
	);
}
add_action( 'rest_api_init', __NAMESPACE__ . '\\register_routes' );

// ── Curated response handlers ────────────────────────────────────────────────

/**
 * perPage clamped to [1, MAX_PER_PAGE], defaulting to MAX_PER_PAGE.
 */
function clamp_per_page( \WP_REST_Request $request ): int {
	$requested = (int) $request->get_param( 'perPage' );
	if ( $requested <= 0 ) {
		$requested = MAX_PER_PAGE;
	}
	return min( $requested, MAX_PER_PAGE );
}

function post_datetime_iso( \WP_Post $post ): string {
	$dt = get_post_datetime( $post );
	return $dt instanceof \DateTimeImmutable ? $dt->format( \DateTimeInterface::ATOM ) : (string) get_the_date( 'c', $post );
}

/**
 * Project a list of \WP_Post objects to the allowlisted {id,title,status,date,link} shape.
 */
function project_post_list( array $posts ): array {
	$out = array();
	foreach ( $posts as $post ) {
		$out[] = array(
			'id'     => $post->ID,
			'title'  => get_the_title( $post ),
			'status' => $post->post_status,
			'date'   => post_datetime_iso( $post ),
			'link'   => get_permalink( $post ),
		);
	}
	return $out;
}

/**
 * Query published-only posts of a given type, curated + truncation-flagged.
 */
function query_published( string $post_type, \WP_REST_Request $request ): array {
	$per_page = clamp_per_page( $request );
	$search   = sanitize_text_field( (string) $request->get_param( 'search' ) );

	$query_args = array(
		'post_type'      => $post_type,
		'post_status'    => 'publish',
		'posts_per_page' => $per_page,
		'no_found_rows'  => false,
	);
	if ( '' !== $search ) {
		$query_args['s'] = $search;
	}

	$query = new \WP_Query( $query_args );

	return array(
		'items'     => project_post_list( $query->posts ),
		'truncated' => $query->found_posts > $per_page,
	);
}

function handle_posts( \WP_REST_Request $request ): array {
	$result = query_published( 'post', $request );
	return array(
		'posts'     => $result['items'],
		'truncated' => $result['truncated'],
	);
}

function handle_pages( \WP_REST_Request $request ): array {
	$result = query_published( 'page', $request );
	return array(
		'pages'     => $result['items'],
		'truncated' => $result['truncated'],
	);
}

function handle_post_types( \WP_REST_Request $request ): array {
	$types = get_post_types( array( 'public' => true ), 'objects' );
	$out   = array();
	foreach ( $types as $slug => $type ) {
		$out[] = array(
			'slug'     => $slug,
			'name'     => isset( $type->labels->name ) ? $type->labels->name : $slug,
			'restBase' => ! empty( $type->rest_base ) ? $type->rest_base : $slug,
		);
	}
	return array( 'types' => $out );
}

function handle_post( \WP_REST_Request $request ): array {
	$id = (int) $request->get_param( 'id' );
	if ( $id <= 0 ) {
		return array( 'post' => null, 'found' => false );
	}

	$post = get_post( $id );
	// Status-guard: post IDs are sequential/guessable, so drafts, private and
	// trashed posts must answer identically to a missing ID — never leak even
	// a "found but not public" signal.
	if ( ! $post || 'publish' !== $post->post_status ) {
		return array( 'post' => null, 'found' => false );
	}

	// Built manually (not get_the_excerpt()) so no theme/plugin filter or
	// shortcode runs against this API surface — deterministic, curated output.
	$excerpt = '' !== $post->post_excerpt ? $post->post_excerpt : $post->post_content;
	$excerpt = wp_strip_all_tags( $excerpt );
	$excerpt = trim( (string) preg_replace( '/\s+/', ' ', $excerpt ) );
	$excerpt = mb_substr( $excerpt, 0, EXCERPT_MAX_LENGTH );

	return array(
		'post'  => array(
			'id'          => $post->ID,
			'title'       => get_the_title( $post ),
			'status'      => $post->post_status,
			'date'        => post_datetime_iso( $post ),
			'link'        => get_permalink( $post ),
			'excerptText' => $excerpt,
		),
		'found' => true,
	);
}
