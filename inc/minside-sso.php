<?php
/**
 * Min side SSO — inkludert av nettsmed-support-plugin.
 *
 * Minter et kortlevd RS256-JWT for SSO mot minside.nettsmed.no.
 * INERT med mindre wp-config.php-konstanten MINSIDE_SSO_PRIVATE_KEY er definert.
 * Ingen wp_option-fallback for privat nøkkel (fail-closed av sikkerhetshensyn).
 *
 * @package NettsmedSupport
 */

declare( strict_types=1 );

namespace Nettsmed\MinsideSSO;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Konstanter ─────────────────────────────────────────────────────────────

const MINSIDE_URL_DEFAULT = 'https://minside.nettsmed.no';
const SSO_ISSUER          = 'nettsmed-support-plugin';
const SSO_AUD             = 'minside.nettsmed.no';
const SSO_TTL_SECONDS     = 90;   // exp = iat + 90 s (ned fra 600)
const OPTION_SITE_KEY     = 'minside_sso_site_key';
const REQUIRED_CAPABILITY = 'manage_options';
const ADMIN_POST_ACTION   = 'minside_sso_launch';
const NONCE_ACTION        = 'minside_sso_launch';

/**
 * Auto-bounce ved WP first-load: ALLTID av.
 * Aktiver aldri uten SP-initiert state — setter ikke en sesjon uten CSRF-vern.
 */
if ( ! defined( 'MINSIDE_SSO_AUTOBOUNCE' ) ) {
	define( 'MINSIDE_SSO_AUTOBOUNCE', false );
}

// ── Hjelpefunksjoner ────────────────────────────────────────────────────────

/**
 * Mål-URL for minside. Overstyres med wp-config-konstanten MINSIDE_URL.
 */
function minside_url(): string {
	if ( defined( 'MINSIDE_URL' ) && '' !== (string) \MINSIDE_URL ) {
		return rtrim( (string) \MINSIDE_URL, '/' );
	}
	return MINSIDE_URL_DEFAULT;
}

/**
 * Hent site_key. wp-config-konstant MINSIDE_SITE_KEY vinner, ellers option.
 */
function get_site_key(): string {
	if ( defined( 'MINSIDE_SITE_KEY' ) && '' !== (string) \MINSIDE_SITE_KEY ) {
		return (string) \MINSIDE_SITE_KEY;
	}
	return (string) get_option( OPTION_SITE_KEY, '' );
}

/**
 * Hent PEM-nøkkel utelukkende fra wp-config.php-konstanten MINSIDE_SSO_PRIVATE_KEY.
 * Ingen wp_option-fallback — fail-closed.
 */
function get_private_key_pem(): string {
	if ( ! defined( 'MINSIDE_SSO_PRIVATE_KEY' ) || '' === (string) \MINSIDE_SSO_PRIVATE_KEY ) {
		return '';
	}
	$raw = trim( (string) \MINSIDE_SSO_PRIVATE_KEY );
	// Konstanten kan holde rå PEM ELLER base64-encodet PEM.
	if ( '' !== $raw && 0 !== strpos( $raw, '-----BEGIN' ) ) {
		$decoded = base64_decode( $raw, true );
		if ( false !== $decoded && 0 === strpos( trim( $decoded ), '-----BEGIN' ) ) {
			return trim( $decoded );
		}
	}
	return $raw;
}

/**
 * Base64url-enkoding (RFC 7515) — ingen padding, +/ → -_.
 */
function base64url_encode( string $data ): string {
	return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
}

/**
 * Er pluginen ferdig konfigurert (har både site_key og privat nøkkel)?
 */
function is_configured(): bool {
	return '' !== get_site_key() && '' !== get_private_key_pem();
}

// ── Admin-varsel når konstanten mangler ─────────────────────────────────────

/**
 * Vis admin-notice dersom MINSIDE_SSO_PRIVATE_KEY ikke er definert.
 * SSO er deaktivert inntil konstanten finnes i wp-config.php.
 */
function show_key_missing_notice(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	if ( defined( 'MINSIDE_SSO_PRIVATE_KEY' ) && '' !== (string) \MINSIDE_SSO_PRIVATE_KEY ) {
		return;
	}
	echo '<div class="notice notice-error"><p>'
		. esc_html__( 'Min side SSO: MINSIDE_SSO_PRIVATE_KEY-konstanten er ikke definert i wp-config.php — SSO er deaktivert.', 'minside-sso' )
		. '</p></div>';
}
add_action( 'admin_notices', __NAMESPACE__ . '\\show_key_missing_notice' );

// ── Token-minting ───────────────────────────────────────────────────────────

/**
 * Mint et RS256-signert JWT for gjeldende innloggede bruker.
 *
 * Claims: { iss, aud, site_key, sub, iat, exp (+90s), jti (128-bit hex CSPRNG), state }.
 * Signert med sitens private nøkkel via ren openssl — ingen eksterne deps.
 *
 * @param string $state Opak state-verdi fra SP-initiert flow (tom = nonce-beskyttet admin-post).
 * @return string|\WP_Error JWT-strengen, eller WP_Error ved feil.
 */
function mint_token( string $state = '' ) {
	$user = wp_get_current_user();
	if ( ! $user || 0 === $user->ID ) {
		return new \WP_Error( 'not_logged_in', __( 'Ingen innlogget bruker.', 'minside-sso' ) );
	}

	$private_pem = get_private_key_pem();
	if ( '' === $private_pem ) {
		if ( class_exists( '\Sentry\SentrySdk' ) ) {
			\Sentry\captureMessage( 'minside-sso: mint_token kalt uten MINSIDE_SSO_PRIVATE_KEY — SSO deaktivert' );
		}
		return new \WP_Error(
			'no_key',
			__( 'MINSIDE_SSO_PRIVATE_KEY-konstanten er ikke definert. Konfigurer den i wp-config.php.', 'minside-sso' )
		);
	}

	$site_key = get_site_key();
	if ( '' === $site_key ) {
		return new \WP_Error(
			'not_configured',
			__( 'Min side-SSO mangler site_key (MINSIDE_SITE_KEY eller innstillingssiden).', 'minside-sso' )
		);
	}

	$private_key = openssl_pkey_get_private( $private_pem );
	if ( false === $private_key ) {
		return new \WP_Error( 'bad_key', __( 'Kunne ikke lese den private nøkkelen. Sjekk PEM-formatet.', 'minside-sso' ) );
	}

	$now    = time();
	$header = array(
		'alg' => 'RS256',
		'typ' => 'JWT',
	);
	$payload = array(
		'iss'      => SSO_ISSUER,
		'aud'      => SSO_AUD,
		'site_key' => $site_key,
		'sub'      => strtolower( trim( $user->user_email ) ),
		'iat'      => $now,
		'exp'      => $now + SSO_TTL_SECONDS,
		'jti'      => bin2hex( random_bytes( 16 ) ),
		'state'    => $state,
	);

	$segments      = array(
		base64url_encode( (string) wp_json_encode( $header ) ),
		base64url_encode( (string) wp_json_encode( $payload ) ),
	);
	$signing_input = implode( '.', $segments );

	$signature = '';
	$ok        = openssl_sign( $signing_input, $signature, $private_key, OPENSSL_ALGO_SHA256 );
	if ( ! $ok ) {
		return new \WP_Error( 'sign_failed', __( 'Signering av token feilet.', 'minside-sso' ) );
	}

	$segments[] = base64url_encode( $signature );

	return implode( '.', $segments );
}

// ── URL-hjelpere ─────────────────────────────────────────────────────────────

/**
 * Bygg Min side-launch-URL. Rutes gjennom minside sin SP-initierte /sso/start, som
 * setter CSRF-state (når V2 er på) eller bouncer direkte til WP-mint (legacy). Knappen
 * treffer dermed samme state-beskytta flyt som /login og virker både med og uten V2.
 * (Den gamle nonce-beskytta admin-post-handleren beholdes for bakoverkompatibilitet,
 * men brukes ikke lenger herfra — SP-flytens vern er minside-state + cap-sjekk.)
 *
 * @param string $next Same-site-sti portalen skal lande på (f.eks. '/faktura').
 */
function launch_url( string $next = '' ): string {
	$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
	$args = array( 'domain' => $host );
	$next = sanitize_next( $next );
	if ( '' !== $next ) {
		$args['return'] = $next;
	}
	return add_query_arg( $args, minside_url() . '/sso/start' );
}

/**
 * Saniter en «next/return»-verdi til en trygg same-site absolutt sti.
 * Avviser absolutte URL-er, protokoll-relative («//evil»), scheme («javascript:»)
 * og backslash for å hindre open-redirect på portal-siden.
 */
function sanitize_next( $value ): string {
	$v = trim( (string) $value );
	if ( '' === $v ) {
		return '';
	}
	// Strip forbudte tegn FØR sikkerhetssjekker slik at input som «/ /evil.com»
	// ikke overlever stripping som en protokoll-relativ sti («//evil.com»).
	$v = (string) preg_replace( '#[^A-Za-z0-9/_\-.?=&%]#', '', $v );
	if ( '' === $v ) {
		return '';
	}
	if ( 0 !== strpos( $v, '/' ) || 0 === strpos( $v, '//' ) ) {
		return '';
	}
	if ( false !== strpos( $v, '://' ) || false !== strpos( $v, "\\" ) ) {
		return '';
	}
	return $v;
}

// ── Emit SSO POST (no-store, no-cache) ─────────────────────────────────────

/**
 * Skriv ut en self-submitting POST-form som sender tokenet til minside /sso.
 * Tokenet ligger i POST-body (IKKE i URL). Setter Cache-Control: no-store for
 * å hindre at sidebufre lagrer form med token. Avslutter requesten.
 *
 * @param string $token  Signert JWT.
 * @param string $next   Sanitert same-site return-sti (optional).
 */
function emit_sso_post( string $token, string $next = '' ): void {
	if ( ! defined( 'DONOTCACHEPAGE' ) ) {
		define( 'DONOTCACHEPAGE', true );
	}
	nocache_headers();
	// Overstyr med sterkere direktiv etter nocache_headers() (legger til no-store + private).
	header( 'Cache-Control: no-store, no-cache, private', true );
	header( 'Content-Type: text/html; charset=utf-8' );
	header( 'Referrer-Policy: no-referrer' );

	$action = esc_url( minside_url() . '/sso' );
	$next   = sanitize_next( $next );

	echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Åpner Min side…</title></head><body>';
	echo '<form id="minside-sso" method="post" action="' . $action . '">';
	echo '<input type="hidden" name="token" value="' . esc_attr( $token ) . '" />';
	if ( '' !== $next ) {
		echo '<input type="hidden" name="return" value="' . esc_attr( $next ) . '" />';
	}
	echo '<noscript><button type="submit">Fortsett til Min side</button></noscript>';
	echo '</form>';
	echo '<script>document.getElementById("minside-sso").submit();</script>';
	echo '</body></html>';
	exit;
}

// ── Admin-meny ──────────────────────────────────────────────────────────────

/**
 * Branded meny-ikon (hvit Nettsmed-diamant) som data-URI SVG.
 */
function menu_icon(): string {
	$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">'
		. '<path fill="#fff" opacity=".9" d="M10 1.2 18.8 10 10 18.8 1.2 10z"/></svg>';
	return 'data:image/svg+xml;base64,' . base64_encode( $svg );
}

/**
 * Admin-bar-node: «Åpne Min side».
 */
function add_admin_bar_button( \WP_Admin_Bar $bar ): void {
	if ( ! is_user_logged_in() || ! current_user_can( REQUIRED_CAPABILITY ) ) {
		return;
	}
	$bar->add_node(
		array(
			'id'    => 'minside-sso',
			'title' => '<span class="ab-icon dashicons dashicons-id-alt" style="top:2px"></span>'
				. esc_html__( 'Min side', 'minside-sso' ),
			'href'  => launch_url(),
			'meta'  => array(
				'title'  => __( 'Logg inn på minside.nettsmed.no', 'minside-sso' ),
				'target' => '_blank',
			),
		)
	);
}
// Admin-bar button og admin-meny registreres kun når nøkkelkonstanten er definert,
// slik at plugin er helt inert på sites uten MINSIDE_SSO_PRIVATE_KEY.
if ( defined( 'MINSIDE_SSO_PRIVATE_KEY' ) && '' !== (string) \MINSIDE_SSO_PRIVATE_KEY ) {
	add_action( 'admin_bar_menu', __NAMESPACE__ . '\\add_admin_bar_button', 100 );
}

/**
 * Toppnivå «Nettsmed»-seksjon i wp-admin sidebaren.
 */
function register_admin_menu(): void {
	add_menu_page(
		__( 'Min side', 'minside-sso' ),
		__( 'Nettsmed', 'minside-sso' ),
		REQUIRED_CAPABILITY,
		'minside-nettsmed',
		__NAMESPACE__ . '\\render_landing_page',
		menu_icon(),
		3
	);
	add_submenu_page(
		'minside-nettsmed',
		__( 'Min side', 'minside-sso' ),
		__( 'Oversikt', 'minside-sso' ),
		REQUIRED_CAPABILITY,
		'minside-nettsmed',
		__NAMESPACE__ . '\\render_landing_page'
	);
}
if ( defined( 'MINSIDE_SSO_PRIVATE_KEY' ) && '' !== (string) \MINSIDE_SSO_PRIVATE_KEY ) {
	add_action( 'admin_menu', __NAMESPACE__ . '\\register_admin_menu' );
}

// ── Landingsside ─────────────────────────────────────────────────────────────

function render_landing_page(): void {
	if ( ! current_user_can( REQUIRED_CAPABILITY ) ) {
		wp_die( esc_html__( 'Ingen tilgang.', 'minside-sso' ) );
	}

	echo '<div class="wrap">';
	echo '<h1>' . esc_html__( 'Nettsmed – Min side', 'minside-sso' ) . '</h1>';

	if ( ! is_configured() ) {
		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html__( 'Min side-SSO er ikke konfigurert ennå. Definer MINSIDE_SSO_PRIVATE_KEY og MINSIDE_SITE_KEY i wp-config.php.', 'minside-sso' )
		);
		echo '</div>';
		return;
	}

	echo '<p style="font-size:14px;color:#50575e;max-width:60ch">'
		. esc_html__( 'Administrer abonnement, support og drift på minside.nettsmed.no — logg inn med din WordPress-konto.', 'minside-sso' )
		. '</p>';

	printf(
		'<p><a class="button button-primary button-hero" href="%s" target="_blank" rel="noopener">%s</a></p>',
		esc_url( launch_url() ),
		esc_html__( 'Åpne Min side', 'minside-sso' )
	);

	$cards = array(
		array( '/drift', __( 'Trafikk & drift', 'minside-sso' ), __( 'Oppetid, backup og besøkstall.', 'minside-sso' ) ),
		array( '/faktura', __( 'Fakturaer', 'minside-sso' ), __( 'Se og last ned fakturaer (PDF).', 'minside-sso' ) ),
		array( '/support', __( 'Support-saker', 'minside-sso' ), __( 'Følg opp eller opprett en sak.', 'minside-sso' ) ),
	);

	echo '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px">';
	foreach ( $cards as $card ) {
		printf(
			'<a href="%1$s" target="_blank" rel="noopener" style="flex:1;min-width:200px;text-decoration:none;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:16px;color:#1d2327;display:block">'
				. '<strong style="font-size:14px">%2$s →</strong>'
				. '<span style="display:block;margin-top:6px;color:#50575e;font-size:13px">%3$s</span></a>',
			esc_url( launch_url( $card[0] ) ),
			esc_html( $card[1] ),
			esc_html( $card[2] )
		);
	}
	echo '</div>';

	echo '</div>';
}

// ── Admin-post-handler (nonce-beskyttet, ikke SP-initiert) ───────────────────

/**
 * Verifiser nonce + capability, mint token uten state (admin-post-flow), redirect.
 */
function handle_launch(): void {
	if ( ! is_user_logged_in() || ! current_user_can( REQUIRED_CAPABILITY ) ) {
		wp_die( esc_html__( 'Ingen tilgang.', 'minside-sso' ), 403 );
	}

	$nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';
	if ( ! wp_verify_nonce( $nonce, NONCE_ACTION ) ) {
		wp_die( esc_html__( 'Sikkerhetskontroll feilet. Prøv på nytt.', 'minside-sso' ), 403 );
	}

	$token = mint_token();
	if ( is_wp_error( $token ) ) {
		wp_die( esc_html( $token->get_error_message() ) );
	}

	$next = isset( $_REQUEST['next'] ) ? sanitize_next( wp_unslash( $_REQUEST['next'] ) ) : '';
	emit_sso_post( $token, $next );
}
add_action( 'admin_post_' . ADMIN_POST_ACTION, __NAMESPACE__ . '\\handle_launch' );

// ── SP-initiert SSO: ?minside_sso=start ─────────────────────────────────────

/**
 * SP-initiert flow: minside sender brukeren hit med ?minside_sso=start&state=X&return=/sti.
 *
 *  - Ikke innlogget → bounce til WP-login med redirect_to tilbake hit (inkl. state+return).
 *  - Innlogget uten tilgang → 403.
 *  - Innlogget + tilgang → mint token med state-claim + auto-POST til minside /sso.
 */
function maybe_handle_sp_start(): void {
	if ( ! isset( $_GET['minside_sso'] ) || 'start' !== sanitize_key( wp_unslash( $_GET['minside_sso'] ) ) ) {
		return;
	}

	$state  = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
	$return = isset( $_GET['return'] ) ? sanitize_next( wp_unslash( $_GET['return'] ) ) : '';

	// Bygg self-URL med state + return for login-bounce (bevarer SP-flyten etter innlogging).
	$self_args = array( 'minside_sso' => 'start' );
	if ( '' !== $state ) {
		$self_args['state'] = $state;
	}
	if ( '' !== $return ) {
		$self_args['return'] = $return;
	}
	$return_url = home_url( add_query_arg( $self_args, '/' ) );

	if ( ! is_user_logged_in() ) {
		wp_safe_redirect( wp_login_url( $return_url ) );
		exit;
	}

	$cap = apply_filters( 'minside_sso_required_capability', REQUIRED_CAPABILITY );
	if ( ! current_user_can( $cap ) ) {
		wp_die(
			esc_html__( 'Brukeren din har ikke tilgang til Min side. Logg inn med en administratorkonto.', 'minside-sso' ),
			esc_html__( 'Ingen tilgang', 'minside-sso' ),
			array( 'response' => 403 )
		);
	}

	if ( ! is_configured() ) {
		wp_die( esc_html__( 'Min side-SSO er ikke konfigurert på dette nettstedet ennå.', 'minside-sso' ) );
	}

	$token = mint_token( $state );
	if ( is_wp_error( $token ) ) {
		wp_die( esc_html( $token->get_error_message() ) );
	}

	emit_sso_post( $token, $return );
}
add_action( 'template_redirect', __NAMESPACE__ . '\\maybe_handle_sp_start' );

// ── Settings-side ────────────────────────────────────────────────────────────

/**
 * Registrer kun site_key-option.
 * Den private nøkkelen administreres utelukkende via MINSIDE_SSO_PRIVATE_KEY-konstanten
 * i wp-config.php — ingen wp_option-lagring (fail-closed).
 */
function register_settings(): void {
	register_setting(
		'minside_sso',
		OPTION_SITE_KEY,
		array(
			'type'              => 'string',
			'sanitize_callback' => 'sanitize_text_field',
			'default'           => '',
		)
	);
}
add_action( 'admin_init', __NAMESPACE__ . '\\register_settings' );

function add_settings_menu(): void {
	add_submenu_page(
		'minside-nettsmed',
		__( 'Min side SSO – innstillinger', 'minside-sso' ),
		__( 'Innstillinger', 'minside-sso' ),
		REQUIRED_CAPABILITY,
		'minside-sso-settings',
		__NAMESPACE__ . '\\render_settings_page'
	);
}
// Prioritet 11 så parent-menyen (prioritet 10) er registrert først.
if ( defined( 'MINSIDE_SSO_PRIVATE_KEY' ) && '' !== (string) \MINSIDE_SSO_PRIVATE_KEY ) {
	add_action( 'admin_menu', __NAMESPACE__ . '\\add_settings_menu', 11 );
}

function render_settings_page(): void {
	if ( ! current_user_can( REQUIRED_CAPABILITY ) ) {
		wp_die( esc_html__( 'Ingen tilgang.', 'minside-sso' ) );
	}

	$site_key_const = defined( 'MINSIDE_SITE_KEY' );
	$key_defined    = defined( 'MINSIDE_SSO_PRIVATE_KEY' ) && '' !== (string) \MINSIDE_SSO_PRIVATE_KEY;

	echo '<div class="wrap">';
	echo '<h1>' . esc_html__( 'Min side SSO', 'minside-sso' ) . '</h1>';
	echo '<p>' . esc_html__( 'Konfigurer SSO mot minside.nettsmed.no. site_key og public key må også finnes i Turso-tabellen tenant_sites på minside-siden.', 'minside-sso' ) . '</p>';

	echo '<form method="post" action="options.php">';
	settings_fields( 'minside_sso' );

	echo '<table class="form-table" role="presentation"><tbody>';

	// site_key.
	echo '<tr><th scope="row"><label for="' . esc_attr( OPTION_SITE_KEY ) . '">' . esc_html__( 'Site key', 'minside-sso' ) . '</label></th><td>';
	if ( $site_key_const ) {
		echo '<p><em>' . esc_html__( 'Satt via wp-config-konstanten MINSIDE_SITE_KEY (overstyrer dette feltet).', 'minside-sso' ) . '</em></p>';
	} else {
		printf(
			'<input name="%1$s" id="%1$s" type="text" class="regular-text" value="%2$s" />',
			esc_attr( OPTION_SITE_KEY ),
			esc_attr( (string) get_option( OPTION_SITE_KEY, '' ) )
		);
	}
	echo '</td></tr>';

	// Privat nøkkel — kun status, ingen textarea (fail-closed: kun konstant tillatt).
	echo '<tr><th scope="row">' . esc_html__( 'Privat nøkkel', 'minside-sso' ) . '</th><td>';
	if ( $key_defined ) {
		echo '<p class="description">&#x2705; ' . esc_html__( 'MINSIDE_SSO_PRIVATE_KEY er satt via wp-config.php-konstant.', 'minside-sso' ) . '</p>';
	} else {
		echo '<p class="description" style="color:#d63638">&#x26A0;&#xFE0F; '
			. esc_html__( 'MINSIDE_SSO_PRIVATE_KEY er ikke definert. Legg den til i wp-config.php — SSO er deaktivert inntil dette er gjort.', 'minside-sso' )
			. '</p>';
	}
	echo '</td></tr>';

	echo '</tbody></table>';
	submit_button();
	echo '</form>';

	echo '<hr /><h2>' . esc_html__( 'Status', 'minside-sso' ) . '</h2>';
	echo '<p>' . ( is_configured()
		? '&#x2705; ' . esc_html__( 'Konfigurert — klar til bruk.', 'minside-sso' )
		: '&#x26A0;&#xFE0F; ' . esc_html__( 'Ikke ferdig konfigurert.', 'minside-sso' ) ) . '</p>';
	echo '</div>';
}

/*
 * Floating launcher removed (TSK-19103). The branded blue help/«Kontakt oss»
 * bubble (#minside-launcher, wp_footer) is gone — frontend help and contact
 * are now consolidated into the Nora assistant. In wp-admin, Min side lives in
 * the Nora help drawer (ai-help-drawer.php). The admin-bar button, the menu
 * page and the SSO mint are unchanged. The launcher-only helpers
 * (support_email(), minside_accent_color / minside_support_email filters)
 * were dropped with it; launch_url() stays for the admin paths.
 */
