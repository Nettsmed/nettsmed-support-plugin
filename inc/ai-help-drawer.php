<?php
/**
 * Nora — context-aware AI help drawer in wp-admin.
 *
 * Enqueues the shared Nettsmed chat widget (hjelp.nettsmed.no) across wp-admin,
 * passing the current admin screen id and the site's detected stack so the
 * drawer surfaces screen-aware suggestions and weights its answers. The drawer
 * serves public help content, so no auth/token crosses the iframe — the plugin
 * only reports context.
 *
 * @package Nettsmed\Support
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'NETTSMED_HELP_BASE' ) ) {
	// Overridable per-site via wp-config (e.g. a staging help center).
	define( 'NETTSMED_HELP_BASE', 'https://hjelp.nettsmed.no' );
}

/**
 * Detect the active stack as a comma-separated list matching hjelp.nettsmed.no's
 * HelpStack vocabulary: wordpress | elementor | gutenberg | woocommerce | generell.
 *
 * @return string CSV of detected stacks (always includes 'wordpress').
 */
function nettsmed_help_detect_stack() {
	if ( ! function_exists( 'is_plugin_active' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	$stack = array( 'wordpress' );

	if ( is_plugin_active( 'woocommerce/woocommerce.php' ) ) {
		$stack[] = 'woocommerce';
	}

	if ( is_plugin_active( 'elementor/elementor.php' ) || is_plugin_active( 'elementor-pro/elementor-pro.php' ) ) {
		$stack[] = 'elementor';
	}

	// Block editor (Gutenberg) — only meaningful on an editor screen.
	$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
	if ( $screen && method_exists( $screen, 'is_block_editor' ) && $screen->is_block_editor() ) {
		$stack[] = 'gutenberg';
	}

	return implode( ',', array_unique( $stack ) );
}

/**
 * Enqueue the help widget on admin pages, tagged with the current screen + stack.
 *
 * @return void
 */
function nettsmed_help_enqueue_drawer() {
	if ( ! is_user_logged_in() ) {
		return;
	}

	$screen    = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
	$screen_id = $screen ? (string) $screen->id : '';
	$stack     = nettsmed_help_detect_stack();

	// Min side integration — only when the minside-SSO bridge plugin is present
	// and configured on this site. The drawer then shows a Min side section in
	// its top bar; clicking a link asks this parent page (via postMessage) to
	// launch minside over SSO, so no token crosses the iframe.
	$ns      = 'Nettsmed\\MinsideSSO\\';
	$minside = function_exists( $ns . 'launch_url' )
		&& function_exists( $ns . 'is_configured' )
		&& call_user_func( $ns . 'is_configured' );
	$email   = ( $minside && function_exists( $ns . 'support_email' ) )
		? (string) call_user_func( $ns . 'support_email' )
		: '';

	$src = trailingslashit( NETTSMED_HELP_BASE ) . 'widget.js';

	// Version null → no ?ver= query; the widget loader pins itself.
	wp_enqueue_script( 'nettsmed-help-widget', $src, array(), null, true );

	// The widget.js loader is data-* driven; inject the attributes onto its tag.
	add_filter(
		'script_loader_tag',
		function ( $tag, $handle ) use ( $screen_id, $stack, $minside, $email ) {
			if ( 'nettsmed-help-widget' !== $handle ) {
				return $tag;
			}
			$attrs = sprintf(
				' data-base="%s" data-label="%s" data-aria="%s" data-title="%s" data-initial="N" data-screen="%s" data-stack="%s"',
				esc_url( NETTSMED_HELP_BASE ),
				esc_attr__( 'Hjelp', 'nettsmed-support' ),
				esc_attr__( 'Åpne hjelp', 'nettsmed-support' ),
				esc_attr__( 'Nettsmed hjelp', 'nettsmed-support' ),
				esc_attr( $screen_id ),
				esc_attr( $stack )
			);
			if ( $minside ) {
				$attrs .= sprintf( ' data-minside="1" data-email="%s"', esc_attr( $email ) );
			}
			return str_replace( ' src=', $attrs . ' src=', $tag );
		},
		10,
		2
	);

	// Parent-side bridge: the drawer (hjelp.nettsmed.no iframe) asks us to open a
	// Min side section; we map it to the minside-SSO launch URL (minted server-
	// side, nonce included) and open it. Origin-validated against the iframe.
	if ( $minside ) {
		// launch_url() is esc_html'd (built for an href, so its ampersands are
		// &amp;). These URLs go into JS window.open() — a non-HTML context where
		// &amp; would NOT be decoded, breaking the _wpnonce param — so decode them.
		$launch = static function ( $next ) use ( $ns ) {
			return html_entity_decode( (string) call_user_func( $ns . 'launch_url', $next ), ENT_QUOTES );
		};
		$cfg = array(
			'origin' => untrailingslashit( NETTSMED_HELP_BASE ),
			'urls'   => array(
				''         => $launch( '' ),
				'/drift'   => $launch( '/drift' ),
				'/faktura' => $launch( '/faktura' ),
				'/support' => $launch( '/support' ),
			),
		);
		$inline = 'window.__noraMinside=' . wp_json_encode( $cfg ) . ';'
			. '(function(){var C=window.__noraMinside;if(!C)return;'
			. 'window.addEventListener("message",function(e){if(e.origin!==C.origin)return;'
			. 'var d=e.data;if(!d||d.type!=="nettsmed-open-minside")return;'
			. 'var u=C.urls[d.next||""];if(u){window.open(u,"_blank","noopener");}});})();';
		wp_add_inline_script( 'nettsmed-help-widget', $inline, 'after' );
	}
}
add_action( 'admin_enqueue_scripts', 'nettsmed_help_enqueue_drawer' );
