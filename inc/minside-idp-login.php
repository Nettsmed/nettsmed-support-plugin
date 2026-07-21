<?php
/**
 * Min side as IdP for WordPress login.
 *
 * Prototype for TSK-19194. Disabled unless MINSIDE_IDP_ENABLED is true.
 *
 * @package NettsmedSupport
 */

declare( strict_types=1 );

namespace Nettsmed\MinsideIdpLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/contracts.generated.php';
require_once __DIR__ . '/minside-idp-decision.php';

const REST_NAMESPACE = 'nettsmed/v1';
const CALLBACK_ISS   = 'nettsmed-minside';
const CALLBACK_AUD   = 'nettsmed-wp-login';
const CALLBACK_ALG   = 'EdDSA';
const CALLBACK_SKEW  = 30;
const TRANSIENT_PREFIX = 'nettsmed_idp_jti_';
const AUDIT_TABLE     = 'nettsmed_idp_provision_audit';

function enabled(): bool {
	if ( ! defined( 'MINSIDE_IDP_ENABLED' ) ) {
		return false;
	}
	$value = \MINSIDE_IDP_ENABLED;
	return true === $value || 1 === $value || '1' === $value || 'true' === strtolower( (string) $value );
}

function autoprovision_enabled(): bool {
	if ( ! defined( 'MINSIDE_IDP_AUTOPROVISION' ) ) {
		return false;
	}
	$value = \MINSIDE_IDP_AUTOPROVISION;
	return true === $value || 1 === $value || '1' === $value || 'true' === strtolower( (string) $value );
}

function forbidden() {
	return new \WP_Error( 'nettsmed_idp_forbidden', 'Forbidden.', array( 'status' => 403 ) );
}

function is_browser_flow( \WP_REST_Request $request ): bool {
	return '1' === (string) $request->get_param( 'ui' );
}

function redirect_to_login_error( \WP_REST_Request $request ): void {
	$return = safe_return_path( $request->get_param( 'return' ) );
	$url    = add_query_arg( 'minside_idp_error', 'forbidden', wp_login_url( $return ) );
	wp_safe_redirect( $url, 303 );
	exit;
}

function public_key(): string {
	if ( defined( 'MINSIDE_IDP_PUBLIC_KEY' ) && '' !== (string) \MINSIDE_IDP_PUBLIC_KEY ) {
		return (string) \MINSIDE_IDP_PUBLIC_KEY;
	}
	return defined( 'NETTSMED_MINSIDE_IDP_PUBKEY' ) ? (string) \NETTSMED_MINSIDE_IDP_PUBKEY : '';
}

function base64url_decode( string $data ) {
	$remainder = strlen( $data ) % 4;
	if ( 0 !== $remainder ) {
		$data .= str_repeat( '=', 4 - $remainder );
	}
	return base64_decode( strtr( $data, '-_', '+/' ), true );
}

function safe_return_path( $value ): string {
	$raw = trim( (string) $value );
	if ( '' === $raw ) {
		return admin_url();
	}
	$cleaned = (string) preg_replace( '#[^A-Za-z0-9/_\-.?=&%]#', '', $raw );
	if ( '' === $cleaned || 0 !== strpos( $cleaned, '/' ) || 0 === strpos( $cleaned, '//' ) ) {
		return admin_url();
	}
	if ( false !== strpos( $cleaned, '://' ) || false !== strpos( $cleaned, "\\" ) ) {
		return admin_url();
	}
	return home_url( $cleaned );
}

function consume_jti( string $jti, int $exp ): bool {
	if ( '' === $jti ) {
		return false;
	}
	$key = TRANSIENT_PREFIX . hash( 'sha256', $jti );
	if ( false !== get_transient( $key ) ) {
		return false;
	}
	$ttl = max( 1, $exp - time() + CALLBACK_SKEW );
	set_transient( $key, '1', $ttl );
	return true;
}

/**
 * @return array{sub:string,name?:string,role:?string,jti:string}|\WP_Error
 */
function verify_assertion( string $jwt ) {
	if ( ! enabled() ) {
		return forbidden();
	}
	$public_key = public_key();
	if ( '' === $public_key ) {
		return forbidden();
	}

	$parts = explode( '.', trim( $jwt ) );
	if ( 3 !== count( $parts ) ) {
		return forbidden();
	}
	list( $header_b64, $payload_b64, $sig_b64 ) = $parts;

	$header_raw  = base64url_decode( $header_b64 );
	$payload_raw = base64url_decode( $payload_b64 );
	$sig_raw     = base64url_decode( $sig_b64 );
	if ( false === $header_raw || false === $payload_raw || false === $sig_raw ) {
		return forbidden();
	}

	$header  = json_decode( $header_raw, true );
	$payload = json_decode( $payload_raw, true );
	if ( ! is_array( $header ) || ! is_array( $payload ) ) {
		return forbidden();
	}
	if ( ! isset( $header['alg'] ) || CALLBACK_ALG !== $header['alg'] ) {
		return forbidden();
	}

	$pubkey_raw = base64_decode( $public_key, true );
	if ( false === $pubkey_raw || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pubkey_raw ) ) {
		return forbidden();
	}
	if ( ! sodium_crypto_sign_verify_detached( $sig_raw, $header_b64 . '.' . $payload_b64, $pubkey_raw ) ) {
		return forbidden();
	}

	$now = time();
	if ( ! isset( $payload['iss'] ) || CALLBACK_ISS !== $payload['iss'] ) {
		return forbidden();
	}
	if ( ! isset( $payload['aud'] ) || CALLBACK_AUD !== $payload['aud'] ) {
		return forbidden();
	}
	if ( ! isset( $payload['exp'] ) || ( $now - CALLBACK_SKEW ) > (int) $payload['exp'] ) {
		return forbidden();
	}
	if ( ! isset( $payload['iat'] ) || (int) $payload['iat'] > ( $now + CALLBACK_SKEW ) ) {
		return forbidden();
	}
	if ( ! isset( $payload['jti'] ) || ! consume_jti( (string) $payload['jti'], (int) $payload['exp'] ) ) {
		return forbidden();
	}

	$site_key = \Nettsmed\MinsideSSO\get_site_key();
	if ( '' === $site_key || ! isset( $payload['site_key'] ) || ! hash_equals( $site_key, (string) $payload['site_key'] ) ) {
		return forbidden();
	}

	$sub = isset( $payload['sub'] ) ? sanitize_email( strtolower( trim( (string) $payload['sub'] ) ) ) : '';
	if ( '' === $sub || ! is_email( $sub ) ) {
		return forbidden();
	}

	$role = isset( $payload['role'] ) && is_string( $payload['role'] ) ? $payload['role'] : null;

	$out = array(
		'sub'  => $sub,
		'role' => $role,
		'jti'  => (string) $payload['jti'],
	);
	if ( isset( $payload['name'] ) && '' !== trim( (string) $payload['name'] ) ) {
		$out['name'] = sanitize_text_field( (string) $payload['name'] );
	}
	return $out;
}

function reject_login( \WP_REST_Request $request, string $reason ) {
	if ( class_exists( '\Sentry\SentrySdk' ) ) {
		\Sentry\captureMessage( 'minside-idp: login rejected — ' . $reason );
	}
	if ( is_browser_flow( $request ) ) {
		redirect_to_login_error( $request );
	}
	return forbidden();
}

function record_provision_audit( string $email, int $wp_user_id, string $role_claim, string $jti ): void {
	global $wpdb;

	$table = $wpdb->prefix . AUDIT_TABLE;

	$wpdb->query(
		"CREATE TABLE IF NOT EXISTS {$table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(190) NOT NULL,
			wp_user_id BIGINT UNSIGNED NOT NULL,
			role_claim VARCHAR(20) NOT NULL,
			jti VARCHAR(64) NOT NULL,
			created_at DATETIME NOT NULL
		) {$wpdb->get_charset_collate()}"
	);

	$wpdb->insert(
		$table,
		array(
			'email'      => $email,
			'wp_user_id' => $wp_user_id,
			'role_claim' => $role_claim,
			'jti'        => $jti,
			'created_at' => current_time( 'mysql', true ),
		),
		array( '%s', '%d', '%s', '%s', '%s' )
	);
}

/**
 * @return int|\WP_Error
 */
function provision_user( string $email, string $role_claim, string $jti ) {
	$user_id = wp_insert_user(
		array(
			'user_login' => $email,
			'user_email' => $email,
			'user_pass'  => wp_generate_password( 32, true, true ),
			'role'       => 'simpel_admin',
		)
	);
	if ( is_wp_error( $user_id ) ) {
		return $user_id;
	}

	record_provision_audit( $email, (int) $user_id, $role_claim, $jti );

	return (int) $user_id;
}

function handle_login( \WP_REST_Request $request ) {
	$assertion = (string) $request->get_param( 'assertion' );
	$verified  = verify_assertion( $assertion );
	if ( is_wp_error( $verified ) ) {
		if ( is_browser_flow( $request ) ) {
			redirect_to_login_error( $request );
		}
		return $verified;
	}

	$user          = get_user_by( 'email', $verified['sub'] );
	$user_exists   = $user instanceof \WP_User;
	$user_is_admin = $user_exists && user_can( $user, 'manage_options' );

	$decision = \Nettsmed\MinsideIdpDecision\decide(
		$verified['role'],
		$user_exists,
		$user_is_admin,
		autoprovision_enabled()
	);

	if ( 'reject' === $decision['action'] ) {
		return reject_login( $request, $decision['reason'] );
	}

	if ( 'provision' === $decision['action'] ) {
		$user_id = provision_user( $verified['sub'], (string) $verified['role'], $verified['jti'] );
		if ( is_wp_error( $user_id ) ) {
			return reject_login( $request, 'provision-failed' );
		}
		$user = get_user_by( 'id', $user_id );
		if ( ! $user instanceof \WP_User ) {
			return reject_login( $request, 'provision-failed' );
		}
	}

	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, false, is_ssl() );

	$return = safe_return_path( $request->get_param( 'return' ) );
	wp_safe_redirect( $return, 303 );
	exit;
}

function register_routes(): void {
	register_rest_route(
		REST_NAMESPACE,
		'/idp/login',
		array(
			'methods'             => \WP_REST_Server::CREATABLE,
			'callback'            => __NAMESPACE__ . '\\handle_login',
			'permission_callback' => '__return_true',
			'args'                => array(
				'assertion' => array(
					'required'          => true,
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
				),
				'return'    => array(
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
				),
				'ui'        => array(
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
				),
			),
		)
	);
}
add_action( 'rest_api_init', __NAMESPACE__ . '\\register_routes' );

function render_login_error_message( string $message ): string {
	if ( ! isset( $_GET['minside_idp_error'] ) || 'forbidden' !== (string) wp_unslash( $_GET['minside_idp_error'] ) ) {
		return $message;
	}
	$error = '<div id="login_error">Innlogging med Min side ble avvist. Bruk vanlig WordPress-innlogging, eller prøv med en Min side-bruker som finnes i WordPress og ikke er administrator.</div>';
	return $error . $message;
}
add_filter( 'login_message', __NAMESPACE__ . '\\render_login_error_message' );

function login_url( string $return = '' ): string {
	$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
	$args = array( 'domain' => $host );
	if ( '' !== $return ) {
		$args['return'] = $return;
	}
	return add_query_arg( $args, \Nettsmed\MinsideSSO\minside_url() . '/idp/authorize' );
}

function render_login_button(): void {
	if ( ! enabled() || ! \Nettsmed\MinsideSSO\is_configured() ) {
		return;
	}
	$return = isset( $_REQUEST['redirect_to'] )
		? \Nettsmed\MinsideSSO\sanitize_next( wp_unslash( $_REQUEST['redirect_to'] ) )
		: '/wp-admin/';

	echo '<p style="margin:16px 0;text-align:center">';
	printf(
		'<a class="button button-large" style="width:100%%;text-align:center" href="%s">%s</a>',
		esc_url( login_url( $return ) ),
		esc_html__( 'Logg inn med Min side', 'nettsmed-support' )
	);
	echo '</p>';
}
add_action( 'login_form', __NAMESPACE__ . '\\render_login_button' );
